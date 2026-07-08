# Changelog

All notable changes to rDNS are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.17.14] – [1.17.17] - 2026-07-08

Profiling-driven optimization of the cached UDP hot path ([#86](https://github.com/ZerosAndOnesLLC/rDNS/issues/86)). A fair benchmark against **multi-threaded** Unbound 1.19 (earlier numbers had compared against single-threaded Unbound) showed rDNS ~0.85–0.97× of Unbound; `perf` traced ~33% of per-query CPU to allocation and SipHash. These changes bring rDNS to parity (peak ~640K QPS, ahead at low concurrency). Fixes A–C are byte-identical to previous output.

### Changed
- **1.17.14 (A+B)** — `DnsName::encode_compressed` no longer allocates a throwaway `Vec<String>` on every compression probe (borrow `&[String]` instead). Replaced Rust's default SipHash with a small inline FxHash (`src/fasthash.rs`, no new dependency) for the cache shards and the name-compression map, and hash the cache shard key once instead of twice.
- **1.17.15 (C)** — the cache stores `Arc<CacheEntry>`; hits share the entry (one refcount bump) instead of deep-cloning every record `Vec`.
- **1.17.16 (D)** — cache hits no longer re-encode the response. The wire body (question + records, compression resolved, TTL placeholders) is built once, lazily, and memoized on the entry; hits `memcpy` it and patch the recorded TTL offsets. Byte-identical output; covered by new `cached_wire_tests`.
- **1.17.17 (E)** — UDP recv-worker default retuned to ~3/4 of cores (was `cores/2` capped at 16; one-per-core measurably regressed under load). New `RDNS_UDP_WORKERS` env override.
- README/BENCHMARKS/site benchmarks refreshed to the honest multi-threaded-Unbound comparison.

## [1.17.13] - 2026-07-08

### Added
- `bench/throughput.sh` — peak-throughput benchmark that sweeps client
  concurrency against a fixed sender-thread pool to find each server's
  saturation point, complementing the latency-focused `bench/run.sh`. The
  sender thread count is decoupled from client count so the co-located load
  generator does not starve the server of CPU.

### Changed
- README: refreshed performance figures to the v1.17.x peak-throughput
  benchmark — 570K QPS at ~130 µs, 2.5–2.9× faster than Unbound on identical
  hardware.

## [1.17.12] - 2026-07-07

### Changed
- Updated all dependencies to their latest Rust 1.96-compatible versions
  (rustls, bytes, anyhow, getrandom, time, rand, and others) and pruned a
  stale wit-bindgen/wasm build-dependency tree. No public API or configuration
  changes.
