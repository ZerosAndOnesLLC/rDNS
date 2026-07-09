# Changelog

All notable changes to rDNS are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.17.20] - 2026-07-08

First crates.io release since 1.17.11 — bundles every change from 1.17.12
through 1.17.20 (dependency refresh, the hot-path optimization round, and
batched UDP I/O).

### Changed
- Packaging: exclude the marketing site (`docs/`), benchmark harness
  (`bench/`), and internal notes from the published crate — 135 → 69 files.

## [1.17.19] - 2026-07-08

### Added
- **Batched UDP I/O (Linux).** The dormant `recvmmsg`/`sendmmsg` module is now
  wired into the UDP recv path: one syscall drains up to 64 datagrams per
  reactor wakeup and cache-hit replies are sent in a single `sendmmsg`,
  reducing per-datagram syscall overhead. Per-datagram behavior is unchanged.
  New `RDNS_UDP_BATCH` env var: `0` forces the per-datagram loop, `N` sets the
  batch size; default is batched. Non-Linux platforms keep the per-datagram
  loop. On a busy co-located test rig the throughput delta is within noise
  (each `SO_REUSEPORT` worker rarely has more than 1–2 packets queued per
  wakeup at steady state); the win shows on quieter/bare-metal hosts and under
  bursts, where the syscall count actually drops.

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
