use std::net::IpAddr;

/// A CIDR network prefix for access control.
#[derive(Debug, Clone)]
struct CidrEntry {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrEntry {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX
                    .checked_shl(32 - self.prefix_len as u32)
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX
                    .checked_shl(128 - self.prefix_len as u32)
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(addr) & mask
            }
            _ => false, // v4 vs v6 mismatch
        }
    }
}

/// Access control list for recursion.
/// If the ACL is empty, all sources are allowed (open resolver — not recommended).
/// If populated, only matching source IPs may use recursion.
#[derive(Debug, Clone)]
pub struct RecursionAcl {
    entries: Vec<CidrEntry>,
}

impl RecursionAcl {
    /// Parse an ACL from a list of CIDR strings (e.g., ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]).
    pub fn from_cidrs(cidrs: &[String]) -> Self {
        let entries = cidrs
            .iter()
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }
                let (addr_str, prefix_len) = if let Some(idx) = s.find('/') {
                    let prefix: u8 = s[idx + 1..].parse().ok()?;
                    (&s[..idx], prefix)
                } else {
                    // No prefix — treat as host
                    let addr: IpAddr = s.parse().ok()?;
                    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
                    return Some(CidrEntry {
                        addr,
                        prefix_len: max_prefix,
                    });
                };
                let addr: IpAddr = addr_str.parse().ok()?;
                Some(CidrEntry { addr, prefix_len })
            })
            .collect();
        Self { entries }
    }

    /// Check if a source IP is allowed to use recursion.
    /// Returns `true` if the ACL is empty (allow all) or if the IP matches any entry.
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        self.entries.iter().any(|e| e.contains(ip))
    }

    /// Whether the ACL has any entries configured.
    pub fn is_configured(&self) -> bool {
        !self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_empty_acl_allows_all() {
        let acl = RecursionAcl::from_cidrs(&[]);
        assert!(acl.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(acl.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_cidr_matching() {
        let acl = RecursionAcl::from_cidrs(&[
            "10.0.0.0/8".to_string(),
            "192.168.1.0/24".to_string(),
            "::1/128".to_string(),
        ]);

        // Allowed
        assert!(acl.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(acl.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(acl.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(acl.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Denied
        assert!(!acl.is_allowed(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
        assert!(!acl.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!acl.is_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_host_entry() {
        let acl = RecursionAcl::from_cidrs(&["127.0.0.1".to_string()]);
        assert!(acl.is_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!acl.is_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
    }

    #[test]
    fn test_ipv6_cidr() {
        let acl = RecursionAcl::from_cidrs(&["fd00::/8".to_string()]);
        assert!(acl.is_allowed("fd00::1".parse().unwrap()));
        assert!(acl.is_allowed("fdff::1".parse().unwrap()));
        assert!(!acl.is_allowed("fe80::1".parse().unwrap()));
    }
}
