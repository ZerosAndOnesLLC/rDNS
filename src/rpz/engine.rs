use super::policy::{PolicyAction, RpzRule, RpzTrigger, action_from_rdata};
use crate::protocol::header::Header;
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::opcode::Opcode;
use crate::protocol::rcode::Rcode;
use crate::protocol::rdata::RData;
use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// RPZ engine that checks queries against loaded policy zones.
#[derive(Clone)]
pub struct RpzEngine {
    inner: Arc<RwLock<RpzState>>,
}

struct RpzState {
    rules: Vec<RpzRule>,
    zone_count: usize,
}

impl RpzEngine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RpzState {
                rules: Vec::new(),
                zone_count: 0,
            })),
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
        let _origin = zone_name.clone();
        let zone_suffix = format!(".{}", zone_name.to_dotted().trim_end_matches('.'));
        let mut new_rules = Vec::new();

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

            new_rules.push(RpzRule { trigger, action });
        }

        let count = new_rules.len();
        let mut state = self.inner.write().unwrap();
        state.rules.extend(new_rules);
        state.zone_count += 1;

        Ok(count)
    }

    /// Check a query name against all RPZ rules.
    /// Returns the first matching policy action, or None if no rules match.
    pub fn check(&self, qname: &DnsName) -> Option<PolicyAction> {
        let state = self.inner.read().unwrap();

        // Check exact matches first (higher priority), then wildcards
        for rule in &state.rules {
            if matches!(rule.trigger, RpzTrigger::QName(_)) && rule.matches(qname) {
                return Some(rule.action.clone());
            }
        }

        for rule in &state.rules {
            if matches!(rule.trigger, RpzTrigger::QNameWildcard(_)) && rule.matches(qname) {
                return Some(rule.action.clone());
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
                // Return empty — caller should not send a response
                Some(Message {
                    header: Header {
                        id: 0,
                        qr: true,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: false,
                        ra: false,
                        ad: false,
                        cd: false,
                        rcode: Rcode::NoError,
                        qd_count: 0,
                        an_count: 0,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: vec![],
                    answers: vec![],
                    authority: vec![],
                    additional: vec![],
                })
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

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.inner.read().unwrap().rules.len()
    }

    /// Clear all rules.
    pub fn clear(&self) {
        let mut state = self.inner.write().unwrap();
        state.rules.clear();
        state.zone_count = 0;
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
}
