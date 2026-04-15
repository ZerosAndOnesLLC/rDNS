use super::events::{BlockEvent, BlockEvents};
use super::policy::{PolicyAction, RpzTrigger, action_from_rdata};
use crate::protocol::header::Header;
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::opcode::Opcode;
use crate::protocol::rcode::Rcode;
use crate::protocol::rdata::RData;
use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-zone hit counter shared across all rules belonging to the zone.
type ZoneCounter = Arc<AtomicU64>;

/// Snapshot of statistics for a single RPZ zone.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZoneStat {
    pub name: String,
    pub rules: u64,
    pub hits: u64,
}

/// Persistent record of a loaded zone — survives `clear()` and reloads,
/// keyed by zone name. Holds the source path so [`reload_all`] can rebuild.
#[derive(Clone)]
struct ZoneInfo {
    name: String,
    rules: u64,
    counter: ZoneCounter,
    source_path: Option<PathBuf>,
}

/// Rule payload stored alongside each match key.
/// Hot path: match → counter.fetch_add → return action.
#[derive(Clone)]
struct RuleEntry {
    action: PolicyAction,
    counter: ZoneCounter,
    zone_name: Arc<str>,
}

/// RPZ engine. Cheap to clone — internally `Arc`s.
#[derive(Clone)]
pub struct RpzEngine {
    /// Lock-free hot read path via ArcSwap. Writers serialize on `write_lock`.
    inner: Arc<ArcSwap<RpzState>>,
    write_lock: Arc<Mutex<()>>,
    /// Persistent zone registry. Counters in here outlive the rule state.
    zones: Arc<RwLock<HashMap<String, ZoneInfo>>>,
    /// Optional event sink for live block streaming.
    events: Arc<RwLock<Option<BlockEvents>>>,
}

#[derive(Clone, Default)]
struct RpzState {
    /// Exact QName matches for O(1) lookup.
    exact_rules: HashMap<DnsName, RuleEntry>,
    /// Wildcard rules stored as (base domain -> entry) for suffix matching.
    wildcard_rules: Vec<(DnsName, RuleEntry)>,
}

impl Default for RpzEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RpzEngine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(RpzState::default())),
            write_lock: Arc::new(Mutex::new(())),
            zones: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(None)),
        }
    }

    /// Install a [`BlockEvents`] sink. Subsequent matches will be recorded.
    pub fn set_event_sink(&self, sink: BlockEvents) {
        *self.events.write() = Some(sink);
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
                source_path: None,
            })
            .counter
            .clone()
    }

    fn set_zone_meta(&self, zone_name: &str, rules: u64, source_path: Option<PathBuf>) {
        let mut zones = self.zones.write();
        if let Some(info) = zones.get_mut(zone_name) {
            info.rules = rules;
            if source_path.is_some() {
                info.source_path = source_path;
            }
        }
    }

    /// Load an RPZ zone file. Records the path so [`reload_all`] can rebuild.
    pub fn load_zone_file(&self, path: &Path, zone_name: &DnsName) -> anyhow::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let count = self.load_zone_inner(&content, zone_name, Some(path.to_path_buf()))?;
        tracing::info!(
            zone = %zone_name,
            rules = count,
            path = %path.display(),
            "Loaded RPZ zone"
        );
        Ok(count)
    }

    /// Load RPZ rules from a string (no source path tracked — used by tests).
    pub fn load_zone_str(&self, content: &str, zone_name: &DnsName) -> anyhow::Result<usize> {
        self.load_zone_inner(content, zone_name, None)
    }

    fn load_zone_inner(
        &self,
        content: &str,
        zone_name: &DnsName,
        source_path: Option<PathBuf>,
    ) -> anyhow::Result<usize> {
        let zone_name_str = zone_name.to_dotted();
        let counter = self.zone_counter(&zone_name_str);
        let zone_arc: Arc<str> = Arc::from(zone_name_str.as_str());

        let (new_exact, new_wildcards) = parse_rpz(content, zone_name, &counter, &zone_arc);
        let count = new_exact.len() + new_wildcards.len();

        // Serialize writers; copy-on-write the state and atomic-swap.
        let _g = self.write_lock.lock();
        let mut next: RpzState = (**self.inner.load()).clone();
        for (name, entry) in new_exact {
            next.exact_rules.insert(name, entry);
        }
        next.wildcard_rules.extend(new_wildcards);
        self.inner.store(Arc::new(next));

        self.set_zone_meta(&zone_name_str, count as u64, source_path);
        Ok(count)
    }

    /// Rebuild the entire RPZ state from disk by re-reading every zone whose
    /// `source_path` is known. Counters and zone registry are preserved.
    /// Returns total rule count after reload.
    pub fn reload_all(&self) -> anyhow::Result<usize> {
        let pairs: Vec<(PathBuf, String, ZoneCounter)> = {
            let zones = self.zones.read();
            zones
                .values()
                .filter_map(|z| {
                    z.source_path
                        .clone()
                        .map(|p| (p, z.name.clone(), z.counter.clone()))
                })
                .collect()
        };

        let mut next = RpzState::default();
        let mut totals: Vec<(String, u64)> = Vec::with_capacity(pairs.len());

        for (path, zone_name_str, counter) in pairs {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(zone = %zone_name_str, path = %path.display(), error = %e, "Reload: failed to read zone file");
                    continue;
                }
            };
            let zone_name = DnsName::from_str(zone_name_str.trim_end_matches('.'))
                .unwrap_or_else(|_| DnsName::root());
            let zone_arc: Arc<str> = Arc::from(zone_name_str.as_str());
            let (exact, wild) = parse_rpz(&content, &zone_name, &counter, &zone_arc);
            let z_total = (exact.len() + wild.len()) as u64;
            for (k, v) in exact {
                next.exact_rules.insert(k, v);
            }
            next.wildcard_rules.extend(wild);
            totals.push((zone_name_str, z_total));
        }

        let total: usize = next.exact_rules.len() + next.wildcard_rules.len();

        let _g = self.write_lock.lock();
        self.inner.store(Arc::new(next));

        // Update per-zone rule counts.
        {
            let mut zones = self.zones.write();
            for z in zones.values_mut() {
                z.rules = 0;
            }
            for (name, n) in totals {
                if let Some(z) = zones.get_mut(&name) {
                    z.rules = n;
                }
            }
        }

        tracing::info!(rules = total, "RPZ state reloaded");
        Ok(total)
    }

    /// Check a query name against all RPZ rules.
    /// On match: bump zone counter, record event, return cloned action.
    pub fn check(&self, qname: &DnsName) -> Option<PolicyAction> {
        let state = self.inner.load();

        if let Some(entry) = state.exact_rules.get(qname) {
            entry.counter.fetch_add(1, Ordering::Relaxed);
            self.notify(qname, &entry.action, &entry.zone_name);
            return Some(entry.action.clone());
        }

        for (base, entry) in &state.wildcard_rules {
            if qname.is_subdomain_of(base) && qname != base {
                entry.counter.fetch_add(1, Ordering::Relaxed);
                self.notify(qname, &entry.action, &entry.zone_name);
                return Some(entry.action.clone());
            }
        }

        None
    }

    fn notify(&self, qname: &DnsName, action: &PolicyAction, zone: &Arc<str>) {
        let guard = self.events.read();
        let Some(events) = guard.as_ref() else { return };
        let action_str = match action {
            PolicyAction::NxDomain => "nxdomain",
            PolicyAction::NoData => "nodata",
            PolicyAction::Passthru => "passthru",
            PolicyAction::Drop => "drop",
            PolicyAction::RedirectA(_)
            | PolicyAction::RedirectAAAA(_)
            | PolicyAction::RedirectCname(_) => "redirect",
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        events.record(BlockEvent {
            ts,
            qname: qname.to_dotted(),
            action: action_str,
            zone: zone.to_string(),
        });
    }

    /// Build a DNS response based on the RPZ policy action.
    pub fn apply_action(&self, action: &PolicyAction, query: &Message) -> Option<Message> {
        let q = query.questions.first()?;
        match action {
            PolicyAction::NxDomain => Some(empty_response(query, Rcode::NxDomain)),
            PolicyAction::NoData => Some(empty_response(query, Rcode::NoError)),
            PolicyAction::Passthru => None,
            PolicyAction::Drop => None,
            PolicyAction::RedirectA(ip) => Some(redirect_response(
                query,
                ResourceRecord {
                    name: q.name.clone(),
                    rtype: RecordType::A,
                    rclass: RecordClass::IN,
                    ttl: 60,
                    rdata: RData::A(*ip),
                },
            )),
            PolicyAction::RedirectAAAA(ip) => Some(redirect_response(
                query,
                ResourceRecord {
                    name: q.name.clone(),
                    rtype: RecordType::AAAA,
                    rclass: RecordClass::IN,
                    ttl: 60,
                    rdata: RData::AAAA(*ip),
                },
            )),
            PolicyAction::RedirectCname(target) => Some(redirect_response(
                query,
                ResourceRecord {
                    name: q.name.clone(),
                    rtype: RecordType::CNAME,
                    rclass: RecordClass::IN,
                    ttl: 60,
                    rdata: RData::CNAME(target.clone()),
                },
            )),
        }
    }

    pub fn rule_count(&self) -> usize {
        let state = self.inner.load();
        state.exact_rules.len() + state.wildcard_rules.len()
    }

    pub fn zone_count(&self) -> usize {
        self.zones.read().len()
    }

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

    pub fn total_hits(&self) -> u64 {
        self.zones
            .read()
            .values()
            .map(|z| z.counter.load(Ordering::Relaxed))
            .sum()
    }

    pub fn clear(&self) {
        let _g = self.write_lock.lock();
        self.inner.store(Arc::new(RpzState::default()));
        let mut zones = self.zones.write();
        for z in zones.values_mut() {
            z.rules = 0;
        }
    }

    pub fn reset_counters(&self) {
        for z in self.zones.read().values() {
            z.counter.store(0, Ordering::Relaxed);
        }
    }
}

fn empty_response(query: &Message, rcode: Rcode) -> Message {
    Message {
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
            rcode,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        },
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn redirect_response(query: &Message, answer: ResourceRecord) -> Message {
    Message {
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
    }
}

fn parse_rpz(
    content: &str,
    zone_name: &DnsName,
    counter: &ZoneCounter,
    zone_arc: &Arc<str>,
) -> (Vec<(DnsName, RuleEntry)>, Vec<(DnsName, RuleEntry)>) {
    let zone_suffix = format!(".{}", zone_name.to_dotted().trim_end_matches('.'));
    let mut exact = Vec::new();
    let mut wild = Vec::new();

    for line in content.lines() {
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('$') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        if tokens.iter().any(|t| t.eq_ignore_ascii_case("SOA"))
            || tokens.iter().enumerate().any(|(i, t)| {
                i > 0 && t.eq_ignore_ascii_case("NS") && !tokens[0].eq_ignore_ascii_case("NS")
            })
        {
            continue;
        }

        let owner = tokens[0];
        let (rtype_idx, _rtype) = tokens
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, t)| matches!(t.to_uppercase().as_str(), "CNAME" | "A" | "AAAA" | "TXT"))
            .unwrap_or((0, &""));

        if rtype_idx == 0 || rtype_idx + 1 >= tokens.len() {
            continue;
        }

        let rtype_str = tokens[rtype_idx].to_uppercase();
        let rdata_str = tokens[rtype_idx + 1];

        let trigger_name = if owner == "@" {
            continue;
        } else if owner.ends_with(&zone_suffix) {
            owner.strip_suffix(&zone_suffix).unwrap_or(owner)
        } else {
            owner
        };

        let trigger = if let Some(stripped) = trigger_name.strip_prefix("*.") {
            let name = DnsName::from_str(stripped)
                .unwrap_or_else(|_| DnsName::from_str("invalid.").unwrap());
            RpzTrigger::QNameWildcard(name)
        } else {
            let name = DnsName::from_str(trigger_name)
                .unwrap_or_else(|_| DnsName::from_str("invalid.").unwrap());
            RpzTrigger::QName(name)
        };

        let action = match rtype_str.as_str() {
            "CNAME" => {
                let target = DnsName::from_str(rdata_str)
                    .unwrap_or_else(|_| DnsName::from_str(".").unwrap());
                action_from_rdata(&RData::CNAME(target))
            }
            "A" => match rdata_str.parse() {
                Ok(ip) => PolicyAction::RedirectA(ip),
                Err(_) => continue,
            },
            "AAAA" => match rdata_str.parse() {
                Ok(ip) => PolicyAction::RedirectAAAA(ip),
                Err(_) => continue,
            },
            _ => continue,
        };

        let entry = RuleEntry {
            action,
            counter: counter.clone(),
            zone_name: zone_arc.clone(),
        };

        match trigger {
            RpzTrigger::QName(name) => exact.push((name, entry)),
            RpzTrigger::QNameWildcard(name) => wild.push((name, entry)),
        }
    }

    (exact, wild)
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
ads.example.com CNAME .
*.tracking.com CNAME .
malware.com A 127.0.0.1
safe.tracking.com CNAME rpz-passthru.
"#;

        let count = engine.load_zone_str(rpz_content, &zone_name).unwrap();
        assert_eq!(count, 4);

        assert_eq!(
            engine.check(&DnsName::from_str("ads.example.com").unwrap()),
            Some(PolicyAction::NxDomain)
        );
        assert_eq!(
            engine.check(&DnsName::from_str("foo.tracking.com").unwrap()),
            Some(PolicyAction::NxDomain)
        );
        assert_eq!(
            engine.check(&DnsName::from_str("malware.com").unwrap()),
            Some(PolicyAction::RedirectA(std::net::Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(
            engine.check(&DnsName::from_str("safe.tracking.com").unwrap()),
            Some(PolicyAction::Passthru)
        );
        assert_eq!(
            engine.check(&DnsName::from_str("clean.example.com").unwrap()),
            None
        );
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
        engine
            .load_zone_str("b.example.com CNAME .\n*.tracker.com CNAME .\n", &mal)
            .unwrap();

        engine.check(&DnsName::from_str("a.example.com").unwrap());
        engine.check(&DnsName::from_str("b.example.com").unwrap());
        engine.check(&DnsName::from_str("x.tracker.com").unwrap());
        engine.check(&DnsName::from_str("y.tracker.com").unwrap());
        engine.check(&DnsName::from_str("nope.example.com").unwrap());

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
        assert_eq!(engine.rule_count(), 0);
        let stats = engine.zone_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].rules, 0);
        assert_eq!(stats[0].hits, 2);

        engine.load_zone_str("blocked.com CNAME .\n", &zone).unwrap();
        engine.check(&DnsName::from_str("blocked.com").unwrap());
        assert_eq!(engine.total_hits(), 3);
    }

    #[test]
    fn test_reload_all_from_files() {
        let engine = RpzEngine::new();
        let dir = tempdir();
        let zone_path = dir.join("test.rpz");
        std::fs::write(&zone_path, "blocked.com CNAME .\n").unwrap();
        let zone_name = DnsName::from_str("file.test").unwrap();
        engine.load_zone_file(&zone_path, &zone_name).unwrap();
        assert_eq!(engine.rule_count(), 1);

        // Bump counter so we can confirm it survives reload.
        engine.check(&DnsName::from_str("blocked.com").unwrap());
        assert_eq!(engine.total_hits(), 1);

        // Edit on disk → reload → rules update, counters retained.
        std::fs::write(&zone_path, "blocked.com CNAME .\nalso.com CNAME .\n").unwrap();
        let total = engine.reload_all().unwrap();
        assert_eq!(total, 2);
        assert_eq!(engine.total_hits(), 1);
        assert!(engine.check(&DnsName::from_str("also.com").unwrap()).is_some());
        assert_eq!(engine.total_hits(), 2);

        std::fs::remove_dir_all(dir).ok();
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rdns-rpz-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn test_event_sink_records_block() {
        let engine = RpzEngine::new();
        let sink = BlockEvents::new();
        engine.set_event_sink(sink.clone());
        let z = DnsName::from_str("z.local").unwrap();
        engine.load_zone_str("blocked.com CNAME .\n", &z).unwrap();
        engine.check(&DnsName::from_str("blocked.com").unwrap());
        let recent = sink.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].qname, "blocked.com.");
        assert_eq!(recent[0].action, "nxdomain");
        assert_eq!(recent[0].zone, "z.local.");
    }
}
