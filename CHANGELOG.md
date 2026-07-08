# Changelog

All notable changes to rDNS are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

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
