use super::policy::{PolicyAction, RpzTrigger, action_from_rdata};
use crate::protocol::header::Header;
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::opcode::Opcode;
use crate::protocol::rcode::Rcode;
use crate::protocol::rdata::RData;
use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-zone hit counter shared across all rules belonging to the zone.
/// Cloning is cheap (Arc bump); fetch_add on the hot path is one relaxed atomic.
type ZoneCounter = Arc<AtomicU64>;

/// Snapshot of statistics for a single RPZ zone, returned by [`RpzEngine::zone_stats`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZoneStat {
    pub name: String,
    pub rules: u64,
    pub hits: u64,
}

/// Internal record of a loaded zone — preserved across reloads keyed by zone name.
struct ZoneInfo {
    name: String,
    rules: u64,
    counter: ZoneCounter,
}

/// Rule payload stored alongside each match key. Keeping the counter on the rule
/// avoids a per-query map lookup — match → bump → return.
#[derive(Clone)]
struct RuleEntry {
    action: PolicyAction,
    counter: ZoneCounter,
}

/// RPZ engine that checks queries against loaded policy zones.
#[derive(Clone)]
pub struct RpzEngine {
    inner: Arc<RwLock<RpzState>>,
    /// Persistent zone registry: name → counter Arc.
    /// Lives outside `RpzState` so counters survive `clear()` / reload.
    zones: Arc<RwLock<HashMap<String, ZoneInfo>>>,
}

struct RpzState {
    /// Exact QName matches for O(1) lookup.
    exact_rules: HashMap<DnsName, RuleEntry>,
    /// Wildcard rules stored as (base domain -> entry) for suffix matching.
    wildcard_rules: Vec<(DnsName, RuleEntry)>,
}

impl RpzEngine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RpzState {
                exact_rules: HashMap::new(),
                wildcard_rules: Vec::new(),
            })),
            zones: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up (or create) the persistent counter for a zone name.
    fn zone_counter(&self, zone_name: &str) -> ZoneCounter {
        let mut zones = self.zones.write();
        zones
            .entry(zone_name.to_string())
            .or_insert_with(|| ZoneInfo {
                name: zone_name.to_string(),
                rules: 0,
                counter: Arc::new(AtomicU64::new(0)),
            })
            .counter
            .clone()
    }

    /// Update the loaded rule count for a zone.
    fn set_zone_rules(&self, zone_name: &str, rules: u64) {
        let mut zones = self.zones.write();
        if let Some(info) = zones.get_mut(zone_name) {
            info.rules = rules;
        }
    }

    /// Load an RPZ zone file. RPZ zone files use standard zone file format
    /// where owner names encode the trigger and RDATA encodes the action.
    pub fn load_zone_file(&self, path: &Path, zone_name: &DnsName) -> anyhow::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let count = self.load_zone_str(&content, zone_name)?;
        tracing::info!(
            zone = %zone_name,
            rules = count,
            path = %path.display(),
            "Loaded RPZ zone"
        );
        Ok(count)
    }

    /// Load RPZ rules from a zone file string.
    pub fn load_zone_str(&self, content: &str, zone_name: &DnsName) -> anyhow::Result<usize> {
        let zone_name_str = zone_name.to_dotted();
        let zone_suffix = format!(".{}", zone_name_str.trim_end_matches('.'));
        let counter = self.zone_counter(&zone_name_str);

        let mut new_exact: Vec<(DnsName, RuleEntry)> = Vec::new();
        let mut new_wildcards: Vec<(DnsName, RuleEntry)> = Vec::new();

        for line in content.lines() {
            let line = line.split(';').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('$') {
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 3 {
                continue;
            }

            // Skip SOA and NS records (zone infrastructure)
            if tokens.iter().any(|t| t.eq_ignore_ascii_case("SOA"))
                || tokens.iter().enumerate().any(|(i, t)| {
                    i > 0 && t.eq_ignore_ascii_case("NS") && !tokens[0].eq_ignore_ascii_case("NS")
                })
            {
                continue;
            }

            // Parse: owner [TTL] [CLASS] TYPE RDATA
            let owner = tokens[0];

            // Find the record type and rdata
            let (rtype_idx, _rtype) = tokens
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, t)| {
                    matches!(
                        t.to_uppercase().as_str(),
                        "CNAME" | "A" | "AAAA" | "TXT"
                    )
                })
                .unwrap_or((0, &""));

            if rtype_idx == 0 || rtype_idx + 1 >= tokens.len() {
                continue;
            }

            let rtype_str = tokens[rtype_idx].to_uppercase();
            let rdata_str = tokens[rtype_idx + 1];

            // Determine the trigger name (strip the RPZ zone suffix from owner)
            let trigger_name = if owner == "@" {
                continue; // Skip apex records (SOA, NS)
            } else if owner.ends_with(&zone_suffix) {
                owner.strip_suffix(&zone_suffix).unwrap_or(owner)
            } else {
                owner
            };

            // Determine trigger type
            let (trigger, _actual_name) = if trigger_name.starts_with("*.") {
                let base = &trigger_name[2..];
                let name = DnsName::from_str(base)
                    .unwrap_or_else(|_| DnsName::from_str("invalid.").unwrap());
                (RpzTrigger::QNameWildcard(name.clone()), name)
            } else {
                let name = DnsName::from_str(trigger_name)
                    .unwrap_or_else(|_| DnsName::from_str("invalid.").unwrap());
                (RpzTrigger::QName(name.clone()), name)
            };

            // Parse action from RDATA
            let action = match rtype_str.as_str() {
                "CNAME" => {
                    let target = DnsName::from_str(rdata_str)
                        .unwrap_or_else(|_| DnsName::from_str(".").unwrap());
                    action_from_rdata(&RData::CNAME(target))
                }
                "A" => {
                    if let Ok(ip) = rdata_str.parse() {
                        PolicyAction::RedirectA(ip)
                    } else {
                        continue;
                    }
                }
                "AAAA" => {
                    if let Ok(ip) = rdata_str.parse() {
                        PolicyAction::RedirectAAAA(ip)
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            let entry = RuleEntry { action, counter: counter.clone() };

            match trigger {
                RpzTrigger::QName(name) => new_exact.push((name, entry)),
                RpzTrigger::QNameWildcard(name) => new_wildcards.push((name, entry)),
            }
        }

        let count = new_exact.len() + new_wildcards.len();
        {
            let mut state = self.inner.write();
            for (name, entry) in new_exact {
                state.exact_rules.insert(name, entry);
            }
            state.wildcard_rules.extend(new_wildcards);
        }
        self.set_zone_rules(&zone_name_str, count as u64);

        Ok(count)
    }

    /// Check a query name against all RPZ rules.
    /// Returns the first matching policy action, or None if no rules match.
    /// On match, increments the owning zone's hit counter (one relaxed atomic).
    pub fn check(&self, qname: &DnsName) -> Option<PolicyAction> {
        let state = self.inner.read();

        // O(1) exact match check
        if let Some(entry) = state.exact_rules.get(qname) {
            entry.counter.fetch_add(1, Ordering::Relaxed);
            return Some(entry.action.clone());
        }

        // Wildcard check (still linear but typically far fewer rules)
        for (base, entry) in &state.wildcard_rules {
            if qname.is_subdomain_of(base) && qname != base {
                entry.counter.fetch_add(1, Ordering::Relaxed);
                return Some(entry.action.clone());
            }
        }

        None
    }

    /// Build a DNS response based on the RPZ policy action.
    pub fn apply_action(
        &self,
        action: &PolicyAction,
        query: &Message,
    ) -> Option<Message> {
        let q = query.questions.first()?;

        match action {
            PolicyAction::NxDomain => {
                Some(Message {
                    header: Header {
                        id: query.header.id,
                        qr: true,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: query.header.rd,
                        ra: true,
                        ad: false,
                        cd: false,
                        rcode: Rcode::NxDomain,
                        qd_count: 1,
                        an_count: 0,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: query.questions.clone(),
                    answers: vec![],
                    authority: vec![],
                    additional: vec![],
                })
            }
            PolicyAction::NoData => {
                Some(Message {
                    header: Header {
                        id: query.header.id,
                        qr: true,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: query.header.rd,
                        ra: true,
                        ad: false,
                        cd: false,
                        rcode: Rcode::NoError,
                        qd_count: 1,
                        an_count: 0,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: query.questions.clone(),
                    answers: vec![],
                    authority: vec![],
                    additional: vec![],
                })
            }
            PolicyAction::Passthru => None, // Let normal resolution proceed
            PolicyAction::Drop => {
                // Return None — caller must not send any response (silent drop)
                None
            }
            PolicyAction::RedirectA(ip) => {
                let answer = ResourceRecord {
                    name: q.name.clone(),
                    rtype: RecordType::A,
                    rclass: RecordClass::IN,
                    ttl: 60,
                    rdata: RData::A(*ip),
                };
                Some(Message {
                    header: Header {
                        id: query.header.id,
                        qr: true,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: query.header.rd,
                        ra: true,
                        ad: false,
                        cd: false,
                        rcode: Rcode::NoError,
                        qd_count: 1,
                        an_count: 1,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: query.questions.clone(),
                    answers: vec![answer],
                    authority: vec![],
                    additional: vec![],
                })
            }
            PolicyAction::RedirectAAAA(ip) => {
                let answer = ResourceRecord {
                    name: q.name.clone(),
                    rtype: RecordType::AAAA,
                    rclass: RecordClass::IN,
                    ttl: 60,
                    rdata: RData::AAAA(*ip),
                };
                Some(Message {
                    header: Header {
                        id: query.header.id,
                        qr: true,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: query.header.rd,
                        ra: true,
                        ad: false,
                        cd: false,
                        rcode: Rcode::NoError,
                        qd_count: 1,
                        an_count: 1,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: query.questions.clone(),
                    answers: vec![answer],
                    authority: vec![],
                    additional: vec![],
                })
            }
            PolicyAction::RedirectCname(target) => {
                let answer = ResourceRecord {
                    name: q.name.clone(),
                    rtype: RecordType::CNAME,
                    rclass: RecordClass::IN,
                    ttl: 60,
                    rdata: RData::CNAME(target.clone()),
                };
                Some(Message {
                    header: Header {
                        id: query.header.id,
                        qr: true,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: query.header.rd,
                        ra: true,
                        ad: false,
                        cd: false,
                        rcode: Rcode::NoError,
                        qd_count: 1,
                        an_count: 1,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: query.questions.clone(),
                    answers: vec![answer],
                    authority: vec![],
                    additional: vec![],
                })
            }
        }
    }

    /// Number of loaded rules across all zones.
    pub fn rule_count(&self) -> usize {
        let state = self.inner.read();
        state.exact_rules.len() + state.wildcard_rules.len()
    }

    /// Number of loaded zones.
    pub fn zone_count(&self) -> usize {
        self.zones.read().len()
    }

    /// Snapshot per-zone statistics. Cheap: one read lock + one Vec allocation.
    pub fn zone_stats(&self) -> Vec<ZoneStat> {
        let zones = self.zones.read();
        let mut out: Vec<ZoneStat> = zones
            .values()
            .map(|z| ZoneStat {
                name: z.name.clone(),
                rules: z.rules,
                hits: z.counter.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Total RPZ matches across all zones since process start (or last reset).
    pub fn total_hits(&self) -> u64 {
        self.zones
            .read()
            .values()
            .map(|z| z.counter.load(Ordering::Relaxed))
            .sum()
    }

    /// Clear all rules. Counters are preserved (zone registry stays intact).
    /// Use [`reset_counters`] to also zero the per-zone hit counts.
    pub fn clear(&self) {
        let mut state = self.inner.write();
        state.exact_rules.clear();
        state.wildcard_rules.clear();
        // Mark all zones as having zero rules until they are reloaded.
        let mut zones = self.zones.write();
        for z in zones.values_mut() {
            z.rules = 0;
        }
    }

    /// Zero all per-zone hit counters without touching loaded rules.
    pub fn reset_counters(&self) {
        let zones = self.zones.read();
        for z in zones.values() {
            z.counter.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::record::Question;

    #[test]
    fn test_rpz_load_and_check() {
        let engine = RpzEngine::new();
        let zone_name = DnsName::from_str("rpz.local").unwrap();

        let rpz_content = r#"
$TTL 300
@   SOA localhost. admin.localhost. 1 3600 900 604800 300
@   NS  localhost.
; Block ads.example.com
ads.example.com CNAME .
; Block all of tracking.com
*.tracking.com CNAME .
; Redirect malware.com to sinkhole
malware.com A 127.0.0.1
; Whitelist safe.tracking.com
safe.tracking.com CNAME rpz-passthru.
"#;

        let count = engine.load_zone_str(rpz_content, &zone_name).unwrap();
        assert_eq!(count, 4);

        // Test exact block
        let result = engine.check(&DnsName::from_str("ads.example.com").unwrap());
        assert_eq!(result, Some(PolicyAction::NxDomain));

        // Test wildcard block
        let result = engine.check(&DnsName::from_str("foo.tracking.com").unwrap());
        assert_eq!(result, Some(PolicyAction::NxDomain));

        // Test redirect
        let result = engine.check(&DnsName::from_str("malware.com").unwrap());
        assert_eq!(
            result,
            Some(PolicyAction::RedirectA(std::net::Ipv4Addr::new(127, 0, 0, 1)))
        );

        // Test passthru (exact match takes priority over wildcard)
        let result = engine.check(&DnsName::from_str("safe.tracking.com").unwrap());
        assert_eq!(result, Some(PolicyAction::Passthru));

        // Test no match
        let result = engine.check(&DnsName::from_str("clean.example.com").unwrap());
        assert_eq!(result, None);
    }

    #[test]
    fn test_rpz_apply_nxdomain() {
        let engine = RpzEngine::new();
        let query = Message {
            header: Header {
                id: 0x1234,
                qr: false,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: DnsName::from_str("blocked.com").unwrap(),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        let response = engine.apply_action(&PolicyAction::NxDomain, &query).unwrap();
        assert_eq!(response.header.rcode, Rcode::NxDomain);
        assert_eq!(response.header.id, 0x1234);
        assert!(response.header.rd);
    }

    #[test]
    fn test_per_zone_hit_counters() {
        let engine = RpzEngine::new();
        let ads = DnsName::from_str("ads.local").unwrap();
        let mal = DnsName::from_str("mal.local").unwrap();

        engine.load_zone_str("a.example.com CNAME .\n", &ads).unwrap();
        engine.load_zone_str("b.example.com CNAME .\n*.tracker.com CNAME .\n", &mal).unwrap();

        // Three matches against the malware zone, one against the ads zone.
        engine.check(&DnsName::from_str("a.example.com").unwrap());
        engine.check(&DnsName::from_str("b.example.com").unwrap());
        engine.check(&DnsName::from_str("x.tracker.com").unwrap());
        engine.check(&DnsName::from_str("y.tracker.com").unwrap());
        engine.check(&DnsName::from_str("nope.example.com").unwrap()); // no match

        let stats = engine.zone_stats();
        assert_eq!(stats.len(), 2);
        let ads_stat = stats.iter().find(|s| s.name == "ads.local.").unwrap();
        let mal_stat = stats.iter().find(|s| s.name == "mal.local.").unwrap();
        assert_eq!(ads_stat.hits, 1);
        assert_eq!(ads_stat.rules, 1);
        assert_eq!(mal_stat.hits, 3);
        assert_eq!(mal_stat.rules, 2);
        assert_eq!(engine.total_hits(), 4);
    }

    #[test]
    fn test_counters_persist_across_clear() {
        let engine = RpzEngine::new();
        let zone = DnsName::from_str("test.zone").unwrap();
        engine.load_zone_str("blocked.com CNAME .\n", &zone).unwrap();
        engine.check(&DnsName::from_str("blocked.com").unwrap());
        engine.check(&DnsName::from_str("blocked.com").unwrap());
        assert_eq!(engine.total_hits(), 2);

        engine.clear();
        // After clear, rule count drops to 0 but zone registry + counter remain.
        assert_eq!(engine.rule_count(), 0);
        let stats = engine.zone_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].rules, 0);
        assert_eq!(stats[0].hits, 2);

        // Reload: counter should keep accumulating, not reset.
        engine.load_zone_str("blocked.com CNAME .\n", &zone).unwrap();
        engine.check(&DnsName::from_str("blocked.com").unwrap());
        assert_eq!(engine.total_hits(), 3);
    }

    #[test]
    fn test_reset_counters() {
        let engine = RpzEngine::new();
        let zone = DnsName::from_str("z.local").unwrap();
        engine.load_zone_str("x.com CNAME .\n", &zone).unwrap();
        engine.check(&DnsName::from_str("x.com").unwrap());
        assert_eq!(engine.total_hits(), 1);
        engine.reset_counters();
        assert_eq!(engine.total_hits(), 0);
        // Rules still loaded.
        assert!(engine.check(&DnsName::from_str("x.com").unwrap()).is_some());
        assert_eq!(engine.total_hits(), 1);
    }
}
