# Changelog

All notable changes to rDNS are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Codebase is now clean under `cargo fmt --check` and
  `cargo clippy --all-targets --all-features -- -D warnings`.
- TCP and DNS-over-TLS listeners take a shared `StreamContext` instead of
  separate engine handles; each accepted connection now clones one `Arc`
  rather than five handles. No behavior change.

### Fixed
- Zone files: records spanning multiple lines in parentheses (RFC 1035 §5.1)
  now parse. The usual multi-line SOA layout, including the bundled
  `zones/example.com.zone`, previously failed with `invalid rdata for SOA`.
- Zone files: `;`, `(` and `)` inside quoted strings are no longer treated as
  comment or grouping syntax, so TXT data like `"v=DKIM1; k=rsa; p=..."` is
  kept intact instead of being truncated at the first `;`.
- Unbalanced parentheses in a zone file are reported as a syntax error with
  the line number where the record starts.

## [1.17.24] - 2026-09-26

### Changed
- Dependency refresh: updated `Cargo.lock` to the latest compatible releases
  (thiserror 2.0.21, syn 3.0.6, synstructure 0.14.0, rand 0.10.3, cc 1.5.1,
  smallvec 1.16.2, tokio-test 0.4.6, unicode-ident 1.0.26, among others).
  No source changes.
- Docker: builder image bumped from `rust:1.83-slim` to `rust:1.98-slim-trixie`,
  and the runtime image moved from `debian:bookworm-slim` to
  `debian:trixie-slim` so the glibc versions match between stages.

## [1.17.23] - 2026-09-14

### Changed
- Dependency refresh: updated `Cargo.lock` to the latest compatible releases
  (rustls 0.23.45, aws-lc-rs 1.18.1, aws-lc-sys 0.45.0, clap 4.6.7,
  toml 1.1.6, tokio-rustls 0.26.5, smallvec 1.16.1, tinyvec 1.13.3, among
  others). No source changes.

## [1.17.22] - 2026-08-24

### Changed
- Dependency refresh: updated `Cargo.lock` to the latest compatible releases
  (rustls 0.23.43, rustls-webpki 0.103.15, aws-lc-rs 1.18.0, thiserror 2.0.20,
  clap 4.6.6, tokio 1.53.1, and the futures 0.3.34 / icu 2.3 families, among
  others). No source changes.

## [1.17.21] - 2026-07-28

### Added
- **DNS64 (RFC 6147).** New `[resolver] dns64` / `dns64_prefix` options: when
  a AAAA query returns an empty NoError answer, the resolver re-resolves the
  name for A and synthesizes AAAA records by embedding the IPv4 in the
  configured /96 prefix (RFC 6052; default `64:ff9b::/96`). CNAME chains pass
  through, NXDOMAIN is never synthesized, and the synthetic answer is cached
  positively under the AAAA key. Pair with a NAT64 translator (e.g. AiFw's
  pf af-to NAT64 rules) using the same prefix.
- `RDNS_LOCK_PATH` env var to override the singleton lock file location.

### Changed
- Updated rustls-pki-types to 1.15.

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
