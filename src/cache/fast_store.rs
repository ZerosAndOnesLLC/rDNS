use super::entry::{CacheEntry, CacheKey};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
    /// Seconds past expiry that expired entries remain eligible for
    /// serve-stale (RFC 8767). Zero ⇒ feature disabled; entries evicted
    /// at expiry like a non-serve-stale cache.
    stale_window_secs: AtomicU32,
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
                stale_window_secs: AtomicU32::new(0),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                insertions: AtomicU64::new(0),
                evictions: AtomicU64::new(0),
            }),
        }
    }

    /// Configure serve-stale (RFC 8767) grace window. Expired entries
    /// remain in the cache and are returned by [`lookup_stale`] for up to
    /// this many seconds past their original TTL. `0` disables the
    /// feature; eviction then runs exactly at expiry.
    pub fn set_stale_window(&self, secs: u32) {
        self.inner.stale_window_secs.store(secs, Ordering::Relaxed);
    }

    #[inline]
    fn stale_window(&self) -> u32 {
        self.inner.stale_window_secs.load(Ordering::Relaxed)
    }

    #[inline]
    fn shard_idx(key: &CacheKey) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize & (NUM_SHARDS - 1)
    }

    /// Look up a fresh cache entry. Uses read lock for maximum concurrency.
    /// Returns `None` if not found or expired. Expired entries are not
    /// returned here even if they're still inside the serve-stale window —
    /// serve-stale is deliberately a resolver-level fallback, never a
    /// fast-path shortcut that skips a fresh resolution attempt.
    ///
    /// When serve-stale is disabled (`stale_window_secs == 0`) an expired
    /// entry found here is opportunistically removed to keep the cache
    /// clean. When enabled, we leave the entry in place so `lookup_stale`
    /// can find it after the fresh attempt fails.
    pub fn lookup(&self, key: &CacheKey) -> Option<CacheEntry> {
        let idx = Self::shard_idx(key);
        let stale_window = self.stale_window();

        // Fast path: read lock only
        {
            let shard = self.inner.shards[idx].read();
            if let Some(entry) = shard.get(key) {
                if !entry.is_expired() {
                    self.inner.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.clone());
                }
                // Expired. If stale is enabled, keep the entry in place for
                // lookup_stale; otherwise fall through to opportunistic GC.
                if stale_window > 0 {
                    self.inner.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            } else {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        // Expired and serve-stale is off — remove.
        {
            let mut shard = self.inner.shards[idx].write();
            shard.remove(key);
        }
        self.inner.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Serve-stale lookup (RFC 8767). Returns an entry that is expired but
    /// still within the configured `stale_window_secs`. The resolver calls
    /// this only after fresh resolution fails, so a successful return here
    /// means "we tried upstream and it didn't answer; here's the last
    /// answer we cached."
    ///
    /// Returns `None` when serve-stale is disabled, when the entry is
    /// absent, when the entry is fresh (caller should have used `lookup`),
    /// or when the entry is past the grace window.
    pub fn lookup_stale(&self, key: &CacheKey) -> Option<CacheEntry> {
        let stale_window = self.stale_window();
        if stale_window == 0 {
            return None;
        }
        let idx = Self::shard_idx(key);
        let shard = self.inner.shards[idx].read();
        let entry = shard.get(key)?;
        if entry.is_stale_usable(stale_window) {
            Some(entry.clone())
        } else {
            None
        }
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

            // Enforce max size: drop entries past the stale-serving
            // window first, then oldest-by-insertion if still over.
            // Under memory pressure we favor keeping recently-inserted
            // entries over serve-stale candidates — a stale answer is
            // still better to lose than a fresh one.
            if shard.len() >= max_per_shard {
                let stale_window = self.stale_window();
                let before = shard.len();
                shard.retain(|_, e| !e.is_past_stale_window(stale_window));
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

    /// Evict entries that are past their stale-serving window. When
    /// serve-stale is disabled this reduces to "evict anything expired".
    pub fn evict_expired(&self) {
        let stale_window = self.stale_window();
        let mut evicted = 0usize;
        for shard in &self.inner.shards {
            let mut s = shard.write();
            let before = s.len();
            s.retain(|_, entry| !entry.is_past_stale_window(stale_window));
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
    fn test_stale_lookup_disabled_returns_none() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        let key = make_key("example.com");
        let mut entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(120);
        store.insert(key.clone(), entry);
        // stale disabled by default
        assert!(store.lookup_stale(&key).is_none());
    }

    #[test]
    fn test_stale_lookup_returns_expired_within_window() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        store.set_stale_window(86400);
        let key = make_key("example.com");
        // 10 s past the clamped 60 s TTL.
        let mut entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(70);
        store.insert(key.clone(), entry);
        // Fresh lookup: none.
        assert!(store.lookup(&key).is_none());
        // Stale lookup: entry returned.
        let stale = store.lookup_stale(&key).expect("entry within stale window");
        assert_eq!(stale.answers.len(), 1);
    }

    #[test]
    fn test_stale_lookup_none_past_window() {
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        store.set_stale_window(120); // 2 minute window
        let key = make_key("example.com");
        let mut entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
        // 5 minutes past insertion → 4 minutes past 60 s TTL → beyond 2 min window.
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(300);
        store.insert(key.clone(), entry);
        assert!(store.lookup(&key).is_none());
        assert!(store.lookup_stale(&key).is_none());
    }

    #[test]
    fn test_lookup_does_not_evict_within_stale_window() {
        // Regression: without the "leave-in-place when stale enabled" branch,
        // a miss-that-found-expired would immediately delete the entry and
        // lookup_stale would never see it.
        let store = FastCacheStore::new(1000, 60, 86400, 300);
        store.set_stale_window(86400);
        let key = make_key("example.com");
        let mut entry = make_entry("example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
        entry.inserted_at = std::time::Instant::now() - std::time::Duration::from_secs(120);
        store.insert(key.clone(), entry);
        let _ = store.lookup(&key); // fresh path — expired, must NOT delete
        let stale = store.lookup_stale(&key);
        assert!(stale.is_some(), "serve-stale entry must survive prior fresh lookup");
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
