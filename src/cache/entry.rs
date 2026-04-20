use crate::protocol::rcode::Rcode;
use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
use crate::protocol::name::DnsName;
use std::time::Instant;

/// A cached DNS response entry.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The answer records
    pub answers: Vec<ResourceRecord>,
    /// Authority section records
    pub authority: Vec<ResourceRecord>,
    /// Additional section records
    pub additional: Vec<ResourceRecord>,
    /// Whether this is a negative cache entry (NXDOMAIN or NODATA)
    pub negative: bool,
    /// Original rcode for negative entries (NxDomain vs NoError/NODATA)
    pub negative_rcode: Rcode,
    /// Original TTL in seconds (as received)
    pub original_ttl: u32,
    /// When this entry was inserted
    pub inserted_at: Instant,
    /// Number of times this entry has been accessed (used by old CacheStore)
    #[allow(dead_code)]
    pub hit_count: u64,
}

/// Cache lookup key: (name, type, class)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: DnsName,
    pub rtype: RecordType,
    pub rclass: RecordClass,
}

impl CacheKey {
    pub fn new(name: DnsName, rtype: RecordType, rclass: RecordClass) -> Self {
        Self { name, rtype, rclass }
    }
}

impl CacheEntry {
    pub fn new(
        answers: Vec<ResourceRecord>,
        authority: Vec<ResourceRecord>,
        additional: Vec<ResourceRecord>,
        ttl: u32,
        negative: bool,
        negative_rcode: Rcode,
    ) -> Self {
        Self {
            answers,
            authority,
            additional,
            negative,
            negative_rcode,
            original_ttl: ttl,
            inserted_at: Instant::now(),
            hit_count: 0,
        }
    }

    /// Remaining TTL in seconds. Returns 0 if expired.
    pub fn remaining_ttl(&self) -> u32 {
        let elapsed = self.inserted_at.elapsed().as_secs() as u32;
        self.original_ttl.saturating_sub(elapsed)
    }

    /// Whether this entry has expired (past its original TTL).
    pub fn is_expired(&self) -> bool {
        self.remaining_ttl() == 0
    }

    /// Seconds elapsed since this entry's original TTL ran out. Zero if the
    /// entry is still fresh. Used by the serve-stale path to decide whether
    /// an expired entry is still within the operator-configured grace
    /// window (RFC 8767).
    pub fn staleness_secs(&self) -> u32 {
        let elapsed = self.inserted_at.elapsed().as_secs() as u32;
        elapsed.saturating_sub(self.original_ttl)
    }

    /// True when the entry is expired but still within `stale_window_secs`
    /// of its original TTL. `stale_window_secs == 0` disables serve-stale.
    pub fn is_stale_usable(&self, stale_window_secs: u32) -> bool {
        stale_window_secs > 0
            && self.is_expired()
            && self.staleness_secs() <= stale_window_secs
    }

    /// True when the entry is past `original_ttl + stale_window_secs` and
    /// should no longer be kept, even for serve-stale. Also true whenever
    /// the entry is simply expired and stale is disabled.
    pub fn is_past_stale_window(&self, stale_window_secs: u32) -> bool {
        if !self.is_expired() {
            return false;
        }
        stale_window_secs == 0 || self.staleness_secs() > stale_window_secs
    }

    /// Get the answer records with TTLs adjusted to remaining time.
    pub fn answers_with_adjusted_ttl(&self) -> Vec<ResourceRecord> {
        let remaining = self.remaining_ttl();
        self.answers
            .iter()
            .map(|rr| ResourceRecord {
                name: rr.name.clone(),
                rtype: rr.rtype,
                rclass: rr.rclass,
                ttl: remaining,
                rdata: rr.rdata.clone(),
            })
            .collect()
    }

    /// Get the authority records with TTLs adjusted to remaining time.
    pub fn authority_with_adjusted_ttl(&self) -> Vec<ResourceRecord> {
        let remaining = self.remaining_ttl();
        self.authority
            .iter()
            .map(|rr| ResourceRecord {
                name: rr.name.clone(),
                rtype: rr.rtype,
                rclass: rr.rclass,
                ttl: remaining,
                rdata: rr.rdata.clone(),
            })
            .collect()
    }

    /// Get the additional records with TTLs adjusted to remaining time.
    ///
    /// Currently unused — minimal-responses (RFC-ish: Unbound default)
    /// strips the additional section before sending. Kept symmetric with
    /// its siblings so flipping the policy off remains a one-line change.
    #[allow(dead_code)]
    pub fn additional_with_adjusted_ttl(&self) -> Vec<ResourceRecord> {
        let remaining = self.remaining_ttl();
        self.additional
            .iter()
            .map(|rr| ResourceRecord {
                name: rr.name.clone(),
                rtype: rr.rtype,
                rclass: rr.rclass,
                ttl: remaining,
                rdata: rr.rdata.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::rdata::RData;
    use std::net::Ipv4Addr;

    fn make_a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_str(name).unwrap(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl,
            rdata: RData::A(ip),
        }
    }

    #[test]
    fn test_cache_entry_ttl() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false, Rcode::NoError);

        assert!(!entry.is_expired());
        assert!(entry.remaining_ttl() <= 300);
        assert!(entry.remaining_ttl() > 295); // should still be close to 300
    }

    #[test]
    fn test_cache_entry_adjusted_ttl() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false, Rcode::NoError);

        let adjusted = entry.answers_with_adjusted_ttl();
        assert_eq!(adjusted.len(), 1);
        assert!(adjusted[0].ttl <= 300);
    }

    #[test]
    fn stale_disabled_evicts_immediately_on_expiry() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let mut entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false, Rcode::NoError);
        // Back-date so the entry is definitely expired.
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(400);
        assert!(entry.is_expired());
        assert!(!entry.is_stale_usable(0));
        assert!(entry.is_past_stale_window(0), "stale disabled: past-expiry ⇒ past window");
    }

    #[test]
    fn stale_window_keeps_recently_expired() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let mut entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false, Rcode::NoError);
        // 10 seconds past expiry.
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(310);
        assert!(entry.is_expired());
        assert!(entry.is_stale_usable(86400));
        assert!(!entry.is_past_stale_window(86400));
    }

    #[test]
    fn stale_window_drops_entries_past_cap() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let mut entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false, Rcode::NoError);
        // Two days past expiry; cap is one day.
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(300 + 2 * 86400);
        assert!(entry.is_expired());
        assert!(!entry.is_stale_usable(86400));
        assert!(entry.is_past_stale_window(86400));
    }

    #[test]
    fn fresh_entry_never_stale() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false, Rcode::NoError);
        assert!(!entry.is_expired());
        assert!(!entry.is_stale_usable(86400));
        assert!(!entry.is_past_stale_window(86400));
    }

    #[test]
    fn test_cache_key_equality() {
        let k1 = CacheKey::new(
            DnsName::from_str("example.com").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );
        let k2 = CacheKey::new(
            DnsName::from_str("EXAMPLE.COM").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );
        assert_eq!(k1, k2); // Case insensitive due to DnsName normalization
    }
}
