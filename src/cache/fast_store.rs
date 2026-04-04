use super::entry::{CacheEntry, CacheKey};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Number of cache shards. Power of 2 for fast modulo.
const NUM_SHARDS: usize = 256;

/// High-performance sharded DNS cache using parking_lot RwLock.
/// Optimized for read-heavy workloads (cache hits are ~99% of queries).
#[derive(Clone)]
pub struct FastCacheStore {
    inner: Arc<FastCacheInner>,
}

struct FastCacheInner {
    shards: Vec<RwLock<HashMap<CacheKey, CacheEntry>>>,
    max_entries: usize,
    min_ttl: u32,
    max_ttl: u32,
    negative_ttl: u32,
    hits: AtomicU64,
    misses: AtomicU64,
    insertions: AtomicU64,
    evictions: AtomicU64,
}

impl FastCacheStore {
    pub fn new(max_entries: usize, min_ttl: u32, max_ttl: u32, negative_ttl: u32) -> Self {
        let per_shard = max_entries / NUM_SHARDS + 1;
        let shards = (0..NUM_SHARDS)
            .map(|_| RwLock::new(HashMap::with_capacity(per_shard / 4)))
            .collect();

        Self {
            inner: Arc::new(FastCacheInner {
                shards,
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

    #[inline]
    fn shard_idx(key: &CacheKey) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize & (NUM_SHARDS - 1)
    }

    /// Look up a cache entry. Uses read lock for maximum concurrency.
    /// Returns None if not found or expired.
    pub fn lookup(&self, key: &CacheKey) -> Option<CacheEntry> {
        let idx = Self::shard_idx(key);

        // Fast path: read lock only
        {
            let shard = self.inner.shards[idx].read();
            if let Some(entry) = shard.get(key) {
                if !entry.is_expired() {
                    self.inner.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.clone());
                }
            } else {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        // Expired entry — upgrade to write lock and remove
        {
            let mut shard = self.inner.shards[idx].write();
            shard.remove(key);
        }
        self.inner.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a cache entry with TTL clamping and size enforcement.
    pub fn insert(&self, key: CacheKey, mut entry: CacheEntry) {
        let ttl = if entry.negative {
            entry.original_ttl.min(self.inner.negative_ttl)
        } else {
            entry
                .original_ttl
                .max(self.inner.min_ttl)
                .min(self.inner.max_ttl)
        };
        entry.original_ttl = ttl;

        let idx = Self::shard_idx(&key);
        let max_per_shard = self.inner.max_entries / NUM_SHARDS + 1;
        {
            let mut shard = self.inner.shards[idx].write();

            // Enforce max size: evict expired entries first, then random if still over
            if shard.len() >= max_per_shard {
                let before = shard.len();
                shard.retain(|_, e| !e.is_expired());
                let evicted = before - shard.len();
                if evicted > 0 {
                    self.inner
                        .evictions
                        .fetch_add(evicted as u64, Ordering::Relaxed);
                }
            }
            if shard.len() >= max_per_shard {
                // Still over capacity — evict ~10% of oldest entries by insertion time
                let to_evict = max_per_shard / 10 + 1;
                let mut entries: Vec<(CacheKey, std::time::Instant)> = shard
                    .iter()
                    .map(|(k, v)| (k.clone(), v.inserted_at))
                    .collect();
                entries.sort_by_key(|(_, ts)| *ts); // oldest first
                let mut evicted = 0;
                for (k, _) in entries.into_iter().take(to_evict) {
                    if shard.remove(&k).is_some() {
                        evicted += 1;
                    }
                }
                self.inner
                    .evictions
                    .fetch_add(evicted as u64, Ordering::Relaxed);
            }

            shard.insert(key, entry);
        }
        self.inner.insertions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn flush(&self) {
        let mut total = 0usize;
        for shard in &self.inner.shards {
            let mut s = shard.write();
            total += s.len();
            s.clear();
        }
        self.inner
            .evictions
            .fetch_add(total as u64, Ordering::Relaxed);
    }

    pub fn flush_name(&self, name: &crate::protocol::name::DnsName) {
        for shard in &self.inner.shards {
            let mut s = shard.write();
            s.retain(|k, _| &k.name != name);
        }
    }

    pub fn stats(&self) -> super::store::CacheStats {
        let entries: usize = self.inner.shards.iter().map(|s| s.read().len()).sum();
        super::store::CacheStats {
            entries,
            max_entries: self.inner.max_entries,
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
            insertions: self.inner.insertions.load(Ordering::Relaxed),
            evictions: self.inner.evictions.load(Ordering::Relaxed),
        }
    }

    pub fn evict_expired(&self) {
        let mut evicted = 0usize;
        for shard in &self.inner.shards {
            let mut s = shard.write();
            let before = s.len();
            s.retain(|_, entry| !entry.is_expired());
            evicted += before - s.len();
        }
        if evicted > 0 {
            self.inner
                .evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

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
        CacheEntry::new(vec![rr], vec![], vec![], ttl, false, crate::protocol::rcode::Rcode::NoError)
    }

    #[test]
    fn test_fast_cache_insert_lookup() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        store.insert(key.clone(), entry);

        let result = store.lookup(&key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().answers.len(), 1);
    }

    #[test]
    fn test_fast_cache_miss() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        assert!(store.lookup(&make_key("nonexistent.com")).is_none());
    }

    #[test]
    fn test_fast_cache_stats() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        let key = make_key("example.com");
        let entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        store.insert(key.clone(), entry);
        store.lookup(&key); // hit
        store.lookup(&make_key("miss.com")); // miss

        let stats = store.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_fast_cache_flush() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        for i in 0..100 {
            let name = format!("test{}.com", i);
            store.insert(
                make_key(&name),
                make_entry(&name, Ipv4Addr::new(1, 2, 3, i as u8), 300),
            );
        }
        assert_eq!(store.stats().entries, 100);
        store.flush();
        assert_eq!(store.stats().entries, 0);
    }

    #[test]
    fn test_fast_cache_ttl_clamping() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        let key = make_key("example.com");
        store.insert(key.clone(), make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 10));
        let cached = store.lookup(&key).unwrap();
        assert_eq!(cached.original_ttl, 60); // clamped to min
    }
}
