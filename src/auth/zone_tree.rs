use crate::protocol::name::DnsName;
use super::zone::Zone;
use std::collections::HashMap;

/// A tree of zones indexed by origin name for fast zone lookup.
/// Supports finding the most specific (longest matching) zone for a query name.
#[derive(Debug, Default)]
pub struct ZoneTree {
    zones: HashMap<DnsName, Zone>,
}

impl ZoneTree {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
        }
    }

    /// Insert a zone into the tree.
    pub fn insert(&mut self, zone: Zone) {
        self.zones.insert(zone.origin.clone(), zone);
    }

    /// Remove a zone by origin name.
    pub fn remove(&mut self, origin: &DnsName) -> Option<Zone> {
        self.zones.remove(origin)
    }

    /// Find the best matching zone for a query name.
    /// Returns the zone with the longest matching suffix.
    pub fn find_zone(&self, name: &DnsName) -> Option<&Zone> {
        let labels = name.labels();

        // Try progressively shorter suffixes
        for i in 0..labels.len() {
            let candidate = match DnsName::from_labels(&labels[i..]) {
                Ok(name) => name,
                Err(_) => continue,
            };
            if let Some(zone) = self.zones.get(&candidate) {
                return Some(zone);
            }
        }

        // Try root zone
        self.zones.get(&DnsName::root())
    }

    /// Find a zone by exact origin name.
    pub fn get_zone(&self, origin: &DnsName) -> Option<&Zone> {
        self.zones.get(origin)
    }

    /// Get a mutable reference to a zone by origin name.
    pub fn get_zone_mut(&mut self, origin: &DnsName) -> Option<&mut Zone> {
        self.zones.get_mut(origin)
    }

    /// List all zone origins.
    pub fn zone_names(&self) -> Vec<&DnsName> {
        self.zones.keys().collect()
    }

    /// Number of zones.
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::rdata::SoaData;

    fn make_zone(origin: &str) -> Zone {
        let origin = DnsName::from_str(origin).unwrap();
        Zone::new(
            origin.clone(),
            SoaData {
                mname: DnsName::from_str("ns1.example.com").unwrap(),
                rname: DnsName::from_str("admin.example.com").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 604800,
                minimum: 300,
            },
            3600,
        )
    }

    #[test]
    fn test_zone_tree_find() {
        let mut tree = ZoneTree::new();
        tree.insert(make_zone("example.com"));
        tree.insert(make_zone("sub.example.com"));

        // Should find sub.example.com for www.sub.example.com
        let zone = tree.find_zone(&DnsName::from_str("www.sub.example.com").unwrap());
        assert!(zone.is_some());
        assert_eq!(zone.unwrap().origin.to_dotted(), "sub.example.com.");

        // Should find example.com for www.example.com
        let zone = tree.find_zone(&DnsName::from_str("www.example.com").unwrap());
        assert!(zone.is_some());
        assert_eq!(zone.unwrap().origin.to_dotted(), "example.com.");

        // Should return None for unrelated domain
        let zone = tree.find_zone(&DnsName::from_str("www.other.com").unwrap());
        assert!(zone.is_none());
    }

    #[test]
    fn test_zone_tree_insert_remove() {
        let mut tree = ZoneTree::new();
        tree.insert(make_zone("example.com"));
        assert_eq!(tree.len(), 1);

        tree.remove(&DnsName::from_str("example.com").unwrap());
        assert_eq!(tree.len(), 0);
    }
}
