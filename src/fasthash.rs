//! Small, dependency-free FxHash implementation.
//!
//! Rust's default `HashMap` uses SipHash-1-3, which is DoS-resistant but slow.
//! For internal, bounded, non-adversarial keys — DNS cache keys (name, type,
//! class) and the per-response name-compression map — profiling showed SipHash
//! and its allocations dominating the cached hot path. FxHash is the same
//! non-cryptographic hash `rustc` uses for its own maps: a rotate-xor-multiply
//! over machine words. It is not collision-resistant against a hostile input,
//! so it must only key structures whose size is otherwise bounded (the cache
//! caps entries and evicts; the compression map lives for one response).
//!
//! 64-bit `usize` is assumed, which holds for every platform rDNS targets
//! (Linux/FreeBSD/macOS on amd64/arm64).

use std::hash::{BuildHasherDefault, Hasher};

/// Multiplier constant from rustc-hash (the odd 64-bit golden-ratio prime).
const K: usize = 0x517c_c1b7_2722_0a95;
const ROTATE: u32 = 5;

/// FxHash hasher. Construct via `Default`.
#[derive(Default)]
pub struct FxHasher {
    hash: usize,
}

impl FxHasher {
    #[inline]
    fn add(&mut self, word: usize) {
        self.hash = (self.hash.rotate_left(ROTATE) ^ word).wrapping_mul(K);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[..8]);
            self.add(u64::from_le_bytes(b) as usize);
            bytes = &bytes[8..];
        }
        if bytes.len() >= 4 {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[..4]);
            self.add(u32::from_le_bytes(b) as usize);
            bytes = &bytes[4..];
        }
        if bytes.len() >= 2 {
            let mut b = [0u8; 2];
            b.copy_from_slice(&bytes[..2]);
            self.add(u16::from_le_bytes(b) as usize);
            bytes = &bytes[2..];
        }
        if let Some(&last) = bytes.first() {
            self.add(last as usize);
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as usize);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as usize);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as usize);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i as usize);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash as u64
    }
}

/// `BuildHasher` for [`FxHasher`], usable as the third `HashMap` type param.
pub type FxBuildHasher = BuildHasherDefault<FxHasher>;

/// Hash a single value with FxHash — used to pick a cache shard without
/// paying for SipHash.
#[inline]
pub fn fx_hash<T: std::hash::Hash>(value: &T) -> u64 {
    let mut hasher = FxHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn map_roundtrips() {
        let mut m: HashMap<String, u32, FxBuildHasher> = HashMap::default();
        for i in 0..1000u32 {
            m.insert(format!("key-{i}"), i);
        }
        for i in 0..1000u32 {
            assert_eq!(m.get(&format!("key-{i}")), Some(&i));
        }
        assert_eq!(m.get("missing"), None);
    }

    #[test]
    fn deterministic_and_distributed() {
        // Same input -> same hash.
        assert_eq!(fx_hash(&"example.com"), fx_hash(&"example.com"));
        // Different inputs -> different hashes (no trivial collision).
        assert_ne!(fx_hash(&"example.com"), fx_hash(&"example.net"));
    }
}
