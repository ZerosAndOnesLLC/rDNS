use crate::protocol::name::DnsName;
use crate::protocol::rdata::RData;
use std::net::{Ipv4Addr, Ipv6Addr};

/// RPZ policy action to apply when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    /// Return NXDOMAIN (block the domain)
    NxDomain,
    /// Return NODATA (empty answer, no error)
    NoData,
    /// Pass through to normal resolution (whitelist)
    Passthru,
    /// Redirect to a specific IP address
    RedirectA(Ipv4Addr),
    /// Redirect to a specific IPv6 address
    RedirectAAAA(Ipv6Addr),
    /// Redirect to a specific CNAME
    RedirectCname(DnsName),
    /// Drop the query silently (TCP RST / UDP no response)
    Drop,
}

/// An RPZ rule entry.
#[derive(Debug, Clone)]
pub struct RpzRule {
    /// The trigger pattern (domain name to match)
    pub trigger: RpzTrigger,
    /// The action to take when matched
    pub action: PolicyAction,
}

/// What triggers an RPZ rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpzTrigger {
    /// Match query name exactly
    QName(DnsName),
    /// Match query name as wildcard (*.domain matches all subdomains)
    QNameWildcard(DnsName),
}

impl RpzRule {
    /// Check if this rule matches a query name.
    pub fn matches(&self, qname: &DnsName) -> bool {
        match &self.trigger {
            RpzTrigger::QName(name) => qname == name,
            RpzTrigger::QNameWildcard(base) => {
                let base_labels = base.labels();
                let qname_labels = qname.labels();
                if qname_labels.len() <= base_labels.len() {
                    return false;
                }
                let offset = qname_labels.len() - base_labels.len();
                &qname_labels[offset..] == base_labels
            }
        }
    }
}

/// Determine the policy action from an RPZ zone record.
/// RPZ encodes actions in the RDATA:
/// - CNAME to "." → NXDOMAIN
/// - CNAME to "*." → NODATA
/// - CNAME to "rpz-passthru." → Passthru
/// - CNAME to "rpz-drop." → Drop
/// - A record → Redirect to that IP
/// - AAAA record → Redirect to that IPv6
/// - CNAME to other → Redirect via CNAME
pub fn action_from_rdata(rdata: &RData) -> PolicyAction {
    match rdata {
        RData::CNAME(name) => {
            let dotted = name.to_dotted();
            match dotted.as_str() {
                "." => PolicyAction::NxDomain,
                "*." => PolicyAction::NoData,
                "rpz-passthru." => PolicyAction::Passthru,
                "rpz-drop." => PolicyAction::Drop,
                _ => PolicyAction::RedirectCname(name.clone()),
            }
        }
        RData::A(ip) => PolicyAction::RedirectA(*ip),
        RData::AAAA(ip) => PolicyAction::RedirectAAAA(*ip),
        _ => PolicyAction::NxDomain, // Default: block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qname_match() {
        let rule = RpzRule {
            trigger: RpzTrigger::QName(DnsName::from_str("bad.example.com").unwrap()),
            action: PolicyAction::NxDomain,
        };

        assert!(rule.matches(&DnsName::from_str("bad.example.com").unwrap()));
        assert!(!rule.matches(&DnsName::from_str("good.example.com").unwrap()));
    }

    #[test]
    fn test_wildcard_match() {
        let rule = RpzRule {
            trigger: RpzTrigger::QNameWildcard(DnsName::from_str("example.com").unwrap()),
            action: PolicyAction::NxDomain,
        };

        assert!(rule.matches(&DnsName::from_str("bad.example.com").unwrap()));
        assert!(rule.matches(&DnsName::from_str("deep.sub.example.com").unwrap()));
        assert!(!rule.matches(&DnsName::from_str("example.com").unwrap())); // Exact match doesn't count as wildcard
        assert!(!rule.matches(&DnsName::from_str("other.com").unwrap()));
    }

    #[test]
    fn test_action_from_rdata() {
        assert_eq!(
            action_from_rdata(&RData::CNAME(DnsName::from_str(".").unwrap())),
            PolicyAction::NxDomain
        );
        assert_eq!(
            action_from_rdata(&RData::A(Ipv4Addr::new(127, 0, 0, 1))),
            PolicyAction::RedirectA(Ipv4Addr::new(127, 0, 0, 1))
        );
    }
}
