use crate::protocol::name::DnsName;
use crate::protocol::rdata::SoaData;
use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
use std::collections::HashMap;

/// A DNS zone containing all records for a domain.
#[derive(Debug, Clone)]
pub struct Zone {
    /// Zone origin (e.g., "example.com.")
    pub origin: DnsName,
    /// SOA record for this zone
    pub soa: SoaData,
    /// SOA TTL
    pub soa_ttl: u32,
    /// All resource record sets, keyed by (name, type)
    pub rrsets: HashMap<(DnsName, RecordType), RRSet>,
}

/// A set of resource records with the same name and type.
#[derive(Debug, Clone)]
pub struct RRSet {
    pub name: DnsName,
    pub rtype: RecordType,
    pub rclass: RecordClass,
    pub ttl: u32,
    pub records: Vec<ResourceRecord>,
}

impl Zone {
    pub fn new(origin: DnsName, soa: SoaData, soa_ttl: u32) -> Self {
        Self {
            origin,
            soa,
            soa_ttl,
            rrsets: HashMap::new(),
        }
    }

    /// Add a resource record to this zone.
    pub fn add_record(&mut self, rr: ResourceRecord) {
        let key = (rr.name.clone(), rr.rtype);
        let rrset = self.rrsets.entry(key).or_insert_with(|| RRSet {
            name: rr.name.clone(),
            rtype: rr.rtype,
            rclass: rr.rclass,
            ttl: rr.ttl,
            records: Vec::new(),
        });
        rrset.records.push(rr);
    }

    /// Look up records by name and type.
    pub fn lookup(&self, name: &DnsName, rtype: RecordType) -> Option<&RRSet> {
        self.rrsets.get(&(name.clone(), rtype))
    }

    /// Look up any records for a name (any type).
    pub fn lookup_any(&self, name: &DnsName) -> Vec<&RRSet> {
        self.rrsets
            .iter()
            .filter(|((n, _), _)| n == name)
            .map(|(_, rrset)| rrset)
            .collect()
    }

    /// Check if a name exists in the zone (has any records).
    pub fn name_exists(&self, name: &DnsName) -> bool {
        self.rrsets.keys().any(|(n, _)| n == name)
    }

    /// Check if a name is within this zone (is a subdomain of the origin or equal).
    pub fn contains_name(&self, name: &DnsName) -> bool {
        if name == &self.origin {
            return true;
        }
        let origin_labels = self.origin.labels();
        let name_labels = name.labels();
        if name_labels.len() < origin_labels.len() {
            return false;
        }
        // Check if the name ends with the origin labels
        let offset = name_labels.len() - origin_labels.len();
        &name_labels[offset..] == origin_labels
    }

    /// Find NS records for a delegation point (if any) between the query name and the zone origin.
    pub fn find_delegation(&self, name: &DnsName) -> Option<&RRSet> {
        let origin_len = self.origin.labels().len();
        let name_labels = name.labels();

        // Walk from zone origin down to the query name looking for NS records
        // Skip the zone apex (that's not a delegation)
        for i in (origin_len + 1)..=name_labels.len() {
            let candidate_labels = &name_labels[name_labels.len() - i..];
            let candidate = DnsName::from_labels(candidate_labels);
            if candidate == self.origin {
                continue;
            }
            if let Some(ns_rrset) = self.lookup(&candidate, RecordType::NS) {
                return Some(ns_rrset);
            }
        }
        None
    }

    /// Find wildcard match for a name (e.g., *.example.com matches foo.example.com).
    pub fn find_wildcard(&self, name: &DnsName) -> Option<(&RRSet, DnsName)> {
        let name_labels = name.labels();
        let origin_len = self.origin.labels().len();

        if name_labels.len() <= origin_len {
            return None;
        }

        // Try wildcard at the closest enclosing name
        // e.g., for "foo.bar.example.com", try "*.bar.example.com", then "*.example.com"
        for i in 1..=(name_labels.len() - origin_len) {
            let mut wildcard_labels = vec!["*".to_string()];
            wildcard_labels.extend_from_slice(&name_labels[i..]);
            let wildcard_name = DnsName::from_labels(&wildcard_labels);

            // Check if wildcard has records of any type
            let wildcard_rrsets: Vec<_> = self.lookup_any(&wildcard_name);
            if !wildcard_rrsets.is_empty() {
                // Return the first RRSet found at the wildcard
                return Some((wildcard_rrsets[0], wildcard_name));
            }
        }

        None
    }

    /// Get the SOA record as a ResourceRecord.
    pub fn soa_record(&self) -> ResourceRecord {
        use crate::protocol::rdata::RData;
        ResourceRecord {
            name: self.origin.clone(),
            rtype: RecordType::SOA,
            rclass: RecordClass::IN,
            ttl: self.soa_ttl,
            rdata: RData::SOA(self.soa.clone()),
        }
    }

    /// Get NS records at the zone apex.
    pub fn apex_ns(&self) -> Option<&RRSet> {
        self.lookup(&self.origin, RecordType::NS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::rdata::RData;
    use std::net::Ipv4Addr;

    fn test_zone() -> Zone {
        let origin = DnsName::from_str("example.com").unwrap();
        let soa = SoaData {
            mname: DnsName::from_str("ns1.example.com").unwrap(),
            rname: DnsName::from_str("admin.example.com").unwrap(),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 300,
        };
        let mut zone = Zone::new(origin.clone(), soa, 3600);

        // Add some records
        zone.add_record(ResourceRecord {
            name: origin.clone(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        });

        zone.add_record(ResourceRecord {
            name: DnsName::from_str("www.example.com").unwrap(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        });

        zone
    }

    #[test]
    fn test_zone_lookup() {
        let zone = test_zone();
        let result = zone.lookup(
            &DnsName::from_str("www.example.com").unwrap(),
            RecordType::A,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().records.len(), 1);
    }

    #[test]
    fn test_zone_lookup_miss() {
        let zone = test_zone();
        let result = zone.lookup(
            &DnsName::from_str("missing.example.com").unwrap(),
            RecordType::A,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_zone_contains_name() {
        let zone = test_zone();
        assert!(zone.contains_name(&DnsName::from_str("example.com").unwrap()));
        assert!(zone.contains_name(&DnsName::from_str("www.example.com").unwrap()));
        assert!(zone.contains_name(&DnsName::from_str("deep.sub.example.com").unwrap()));
        assert!(!zone.contains_name(&DnsName::from_str("other.com").unwrap()));
    }

    #[test]
    fn test_zone_name_exists() {
        let zone = test_zone();
        assert!(zone.name_exists(&DnsName::from_str("example.com").unwrap()));
        assert!(zone.name_exists(&DnsName::from_str("www.example.com").unwrap()));
        assert!(!zone.name_exists(&DnsName::from_str("missing.example.com").unwrap()));
    }
}
