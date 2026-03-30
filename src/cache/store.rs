use super::entry::{CacheEntry, CacheKey};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Sharded concurrent DNS cache with TTL-based eviction.
#[derive(Clone)]
pub struct CacheStore {
    inner: Arc<CacheStoreInner>,
}

struct CacheStoreInner {
    /// The main cache storage (DashMap provides sharding internally)
    map: DashMap<CacheKey, CacheEntry>,
    /// Maximum number of entries
    max_entries: usize,
    /// Minimum TTL floor (seconds)
    min_ttl: u32,
    /// Maximum TTL cap (seconds)
    max_ttl: u32,
    /// Negative cache TTL (seconds)
    negative_ttl: u32,
    /// Stats
    hits: AtomicU64,
    misses: AtomicU64,
    insertions: AtomicU64,
    evictions: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub max_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
}

impl CacheStore {
    pub fn new(max_entries: usize, min_ttl: u32, max_ttl: u32, negative_ttl: u32) -> Self {
        Self {
            inner: Arc::new(CacheStoreInner {
                map: DashMap::with_capacity(max_entries / 4),
                max_entries,
                min_ttl,
                max_ttl,
                negative_ttl,
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                insertions: AtomicU64::new(0),
                evictions: AtomicU64::new(0),
            }),
        }
    }

    /// Look up a cache entry. Returns None if not found or expired.
    /// Expired entries are lazily removed on access.
    pub fn lookup(&self, key: &CacheKey) -> Option<CacheEntry> {
        match self.inner.map.get_mut(key) {
            Some(mut entry) => {
                if entry.is_expired() {
                    drop(entry);
                    self.inner.map.remove(key);
                    self.inner.misses.fetch_add(1, Ordering::Relaxed);
                    None
                } else {
                    entry.hit_count += 1;
                    let cloned = entry.clone();
                    self.inner.hits.fetch_add(1, Ordering::Relaxed);
                    Some(cloned)
                }
            }
            None => {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a cache entry with TTL clamping.
    pub fn insert(&self, key: CacheKey, mut entry: CacheEntry) {
        // Clamp TTL to configured bounds
        let ttl = if entry.negative {
            entry.original_ttl.min(self.inner.negative_ttl)
        } else {
            entry
                .original_ttl
                .max(self.inner.min_ttl)
                .min(self.inner.max_ttl)
        };
        entry.original_ttl = ttl;

        // Evict if at capacity
        if self.inner.map.len() >= self.inner.max_entries {
            self.evict_expired();
        }

        // If still at capacity after expired eviction, force-evict oldest
        if self.inner.map.len() >= self.inner.max_entries {
            self.evict_oldest();
        }

        self.inner.map.insert(key, entry);
        self.inner.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Remove a specific entry.
    pub fn remove(&self, key: &CacheKey) -> bool {
        self.inner.map.remove(key).is_some()
    }

    /// Flush all cache entries.
    pub fn flush(&self) {
        let count = self.inner.map.len();
        self.inner.map.clear();
        self.inner.evictions.fetch_add(count as u64, Ordering::Relaxed);
    }

    /// Flush all entries matching a domain name (any type/class).
    pub fn flush_name(&self, name: &crate::protocol::name::DnsName) {
        self.inner.map.retain(|key, _| &key.name != name);
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.inner.map.len(),
            max_entries: self.inner.max_entries,
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
            insertions: self.inner.insertions.load(Ordering::Relaxed),
            evictions: self.inner.evictions.load(Ordering::Relaxed),
        }
    }

    /// Remove all expired entries. Called periodically and on capacity pressure.
    pub fn evict_expired(&self) {
        let before = self.inner.map.len();
        self.inner.map.retain(|_, entry| !entry.is_expired());
        let evicted = before - self.inner.map.len();
        if evicted > 0 {
            self.inner
                .evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

    /// Evict the oldest entries when at capacity (LRU-like by insertion time).
    fn evict_oldest(&self) {
        // Remove ~5% of capacity to avoid constant eviction churn
        let to_remove = (self.inner.max_entries / 20).max(1);
        let mut candidates: Vec<(CacheKey, std::time::Instant)> = self
            .inner
            .map
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().inserted_at))
            .collect();

        candidates.sort_by_key(|(_, inserted)| *inserted);

        for (key, _) in candidates.into_iter().take(to_remove) {
            self.inner.map.remove(&key);
            self.inner.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Spawn a background task that periodically sweeps expired entries.
    pub fn spawn_expiry_task(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                self.evict_expired();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::name::DnsName;
    use crate::protocol::rdata::RData;
    use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
    use std::net::Ipv4Addr;

    fn test_store() -> CacheStore {
        CacheStore::new(1000, 60, 86400, 300)
    }

    fn make_key(name: &str) -> CacheKey {
        CacheKey::new(
            DnsName::from_str(name).unwrap(),
            RecordType::A,
            RecordClass::IN,
        )
    }

    fn make_entry(name: &str, ip: Ipv4Addr, ttl: u32) -> CacheEntry {
        let rr = ResourceRecord {
            name: DnsName::from_str(name).unwrap(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl,
            rdata: RData::A(ip),
        };
        CacheEntry::new(vec![rr], vec![], vec![], ttl, false)
    }

    #[test]
    fn test_insert_and_lookup() {
        let store = test_store();
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        store.insert(key.clone(), entry);

        let result = store.lookup(&key);
        assert!(result.is_some());
        let cached = result.unwrap();
        assert_eq!(cached.answers.len(), 1);
        assert_eq!(cached.hit_count, 1);
    }

    #[test]
    fn test_lookup_miss() {
        let store = test_store();
        let key = make_key("nonexistent.com");
        assert!(store.lookup(&key).is_none());
    }

    #[test]
    fn test_ttl_clamping_min() {
        let store = test_store(); // min_ttl = 60
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 10); // below min

        store.insert(key.clone(), entry);

        let cached = store.lookup(&key).unwrap();
        assert_eq!(cached.original_ttl, 60); // clamped to min
    }

    #[test]
    fn test_ttl_clamping_max() {
        let store = test_store(); // max_ttl = 86400
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 200_000);

        store.insert(key.clone(), entry);

        let cached = store.lookup(&key).unwrap();
        assert_eq!(cached.original_ttl, 86400);
    }

    #[test]
    fn test_remove() {
        let store = test_store();
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        store.insert(key.clone(), entry);
        assert!(store.remove(&key));
        assert!(store.lookup(&key).is_none());
    }

    #[test]
    fn test_flush() {
        let store = test_store();

        for i in 0..10 {
            let name = format!("test{}.com", i);
            store.insert(
                make_key(&name),
                make_entry(&name, Ipv4Addr::new(1, 2, 3, i as u8), 300),
            );
        }

        assert_eq!(store.stats().entries, 10);
        store.flush();
        assert_eq!(store.stats().entries, 0);
    }

    #[test]
    fn test_flush_name() {
        let store = test_store();
        store.insert(
            make_key("example.com"),
            make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 300),
        );
        store.insert(
            make_key("other.com"),
            make_entry("other.com", Ipv4Addr::new(5, 6, 7, 8), 300),
        );

        store.flush_name(&DnsName::from_str("example.com").unwrap());

        assert!(store.lookup(&make_key("example.com")).is_none());
        assert!(store.lookup(&make_key("other.com")).is_some());
    }

    #[test]
    fn test_stats() {
        let store = test_store();
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        store.insert(key.clone(), entry);
        store.lookup(&key);       // hit
        store.lookup(&key);       // hit
        store.lookup(&make_key("miss.com")); // miss

        let stats = store.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.insertions, 1);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_capacity_eviction() {
        let store = CacheStore::new(10, 1, 86400, 300);

        // Fill to capacity
        for i in 0..10 {
            let name = format!("test{}.com", i);
            store.insert(
                make_key(&name),
                make_entry(&name, Ipv4Addr::new(1, 2, 3, i as u8), 300),
            );
        }

        // Insert one more — should trigger eviction
        store.insert(
            make_key("overflow.com"),
            make_entry("overflow.com", Ipv4Addr::new(10, 10, 10, 10), 300),
        );

        // Should not exceed max
        assert!(store.stats().entries <= 10);
    }
}
