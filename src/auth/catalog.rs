use super::zone::Zone;
use super::zone_parser;
use super::zone_tree::ZoneTree;
use crate::protocol::name::DnsName;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Manages all loaded zones. Thread-safe via RwLock for read-heavy workloads.
#[derive(Clone)]
pub struct ZoneCatalog {
    inner: Arc<RwLock<ZoneTree>>,
}

impl ZoneCatalog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ZoneTree::new())),
        }
    }

    /// Load all zone files from a directory.
    /// Expects files named like "example.com.zone".
    pub fn load_directory(&self, dir: &Path) -> anyhow::Result<usize> {
        let mut count = 0;

        if !dir.exists() {
            tracing::warn!(path = %dir.display(), "Zone directory does not exist");
            return Ok(0);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("zone") {
                continue;
            }

            // Derive origin from filename: "example.com.zone" -> "example.com"
            let origin_str = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid zone filename: {}", path.display()))?;

            let origin = DnsName::from_str(origin_str)
                .map_err(|e| anyhow::anyhow!("Invalid zone name '{}': {}", origin_str, e))?;

            match zone_parser::parse_zone_file(&path, &origin) {
                Ok(zone) => {
                    let record_count: usize = zone.rrsets.values().map(|rs| rs.records.len()).sum();
                    tracing::info!(
                        zone = %origin,
                        records = record_count,
                        "Loaded zone"
                    );
                    self.insert(zone);
                    count += 1;
                }
                Err(e) => {
                    tracing::error!(
                        zone = %origin,
                        path = %path.display(),
                        error = %e,
                        "Failed to load zone"
                    );
                }
            }
        }

        Ok(count)
    }

    /// Insert or replace a zone.
    pub fn insert(&self, zone: Zone) {
        let mut tree = self.inner.write().unwrap();
        tree.insert(zone);
    }

    /// Remove a zone by origin.
    pub fn remove(&self, origin: &DnsName) -> Option<Zone> {
        let mut tree = self.inner.write().unwrap();
        tree.remove(origin)
    }

    /// Reload a specific zone from its file.
    pub fn reload_zone(&self, dir: &Path, origin: &DnsName) -> anyhow::Result<()> {
        let filename = format!("{}.zone", origin.to_dotted().trim_end_matches('.'));
        let path = dir.join(filename);

        let zone = zone_parser::parse_zone_file(&path, origin)?;
        self.insert(zone);

        tracing::info!(zone = %origin, "Reloaded zone");
        Ok(())
    }

    /// Find the zone that is authoritative for a given name.
    pub fn find_zone(&self, name: &DnsName) -> Option<Zone> {
        let tree = self.inner.read().unwrap();
        tree.find_zone(name).cloned()
    }

    /// List all zone origins.
    pub fn zone_names(&self) -> Vec<DnsName> {
        let tree = self.inner.read().unwrap();
        tree.zone_names().into_iter().cloned().collect()
    }

    /// Number of loaded zones.
    pub fn zone_count(&self) -> usize {
        let tree = self.inner.read().unwrap();
        tree.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::rdata::SoaData;

    #[test]
    fn test_catalog_insert_find() {
        let catalog = ZoneCatalog::new();

        let origin = DnsName::from_str("example.com").unwrap();
        let zone = Zone::new(
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
        );

        catalog.insert(zone);
        assert_eq!(catalog.zone_count(), 1);

        let found = catalog.find_zone(&DnsName::from_str("www.example.com").unwrap());
        assert!(found.is_some());
        assert_eq!(found.unwrap().origin, origin);
    }
}
