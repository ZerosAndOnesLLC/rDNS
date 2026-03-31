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
    ) -> Self {
        Self {
            answers,
            authority,
            additional,
            negative,
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

    /// Whether this entry has expired.
    pub fn is_expired(&self) -> bool {
        self.remaining_ttl() == 0
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
        let entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false);

        assert!(!entry.is_expired());
        assert!(entry.remaining_ttl() <= 300);
        assert!(entry.remaining_ttl() > 295); // should still be close to 300
    }

    #[test]
    fn test_cache_entry_adjusted_ttl() {
        let rr = make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        let entry = CacheEntry::new(vec![rr], vec![], vec![], 300, false);

        let adjusted = entry.answers_with_adjusted_ttl();
        assert_eq!(adjusted.len(), 1);
        assert!(adjusted[0].ttl <= 300);
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
