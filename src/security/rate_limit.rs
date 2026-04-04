use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// Canonicalize IPv4-mapped IPv6 addresses to their IPv4 equivalent.
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                ip
            }
        }
        _ => ip,
    }
}

/// Per-source-IP rate limiter using a token bucket algorithm.
/// Each IP gets `limit` tokens per second, with a burst capacity of `limit`.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RateLimiterInner>,
}

struct RateLimiterInner {
    /// Per-IP bucket state, sharded to reduce contention.
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
    /// Maximum queries per second per source IP.
    limit: u32,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

const NUM_SHARDS: usize = 64;

impl RateLimiter {
    /// Create a new rate limiter. `limit` is max queries per second per source IP.
    /// A limit of 0 disables rate limiting (all queries allowed).
    pub fn new(limit: u32) -> Self {
        let shards = (0..NUM_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Self {
            inner: Arc::new(RateLimiterInner { shards, limit }),
        }
    }

    /// Check if a query from this IP should be allowed.
    /// Returns `true` if allowed, `false` if rate-limited.
    #[inline]
    pub fn check(&self, ip: IpAddr) -> bool {
        let ip = canonicalize_ip(ip);

        if self.inner.limit == 0 {
            return true;
        }

        let shard_idx = shard_for_ip(&ip);
        let mut shard = self.inner.shards[shard_idx].lock();

        // Prevent memory exhaustion: cap entries per shard.
        // When full, evict the oldest entry to make room instead of rejecting.
        const MAX_ENTRIES_PER_SHARD: usize = 10_000;
        if shard.len() >= MAX_ENTRIES_PER_SHARD && !shard.contains_key(&ip) {
            // Evict the oldest entry
            if let Some(oldest_ip) = shard
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(ip, _)| *ip)
            {
                shard.remove(&oldest_ip);
            }
        }

        let now = Instant::now();
        let limit = self.inner.limit as f64;

        let bucket = shard.entry(ip).or_insert_with(|| Bucket {
            tokens: limit,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * limit).min(limit);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evict stale entries (IPs not seen for > 60 seconds) to prevent memory growth.
    pub fn evict_stale(&self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        let mut evicted = 0usize;
        for shard in &self.inner.shards {
            let mut s = shard.lock();
            let before = s.len();
            s.retain(|_, bucket| bucket.last_refill > cutoff);
            evicted += before - s.len();
        }
        if evicted > 0 {
            tracing::debug!(evicted, "Rate limiter: evicted stale entries");
        }
    }

    /// Spawn a background task to periodically evict stale entries.
    pub fn spawn_cleanup_task(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                self.evict_stale();
            }
        })
    }
}

fn shard_for_ip(ip: &IpAddr) -> usize {
    let hash = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // FNV-1a-inspired hash
            let mut h: u32 = 2166136261;
            for &b in &o {
                h ^= b as u32;
                h = h.wrapping_mul(16777619);
            }
            h
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut h: u32 = 2166136261;
            for &b in &o {
                h ^= b as u32;
                h = h.wrapping_mul(16777619);
            }
            h
        }
    };
    hash as usize & (NUM_SHARDS - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 10 should be allowed (burst capacity)
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        // 11th should be denied
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_disabled_when_zero() {
        let limiter = RateLimiter::new(0);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..10000 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_rate_limiter_different_ips_independent() {
        let limiter = RateLimiter::new(2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        assert!(limiter.check(ip1));
        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1)); // ip1 exhausted

        assert!(limiter.check(ip2)); // ip2 still has tokens
        assert!(limiter.check(ip2));
        assert!(!limiter.check(ip2)); // ip2 exhausted
    }
}
