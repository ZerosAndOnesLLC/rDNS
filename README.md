# rDNS

[![Latest release](https://img.shields.io/github/v/release/ZerosAndOnesLLC/rDNS?label=release&color=blue)](https://github.com/ZerosAndOnesLLC/rDNS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-ce4218?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20FreeBSD%20%7C%20macOS-informational)](#deployment)
[![Performance](https://img.shields.io/badge/perf-640K%20QPS-success)](https://zerosandonesllc.github.io/rDNS/benchmarks/)

A high-performance, security-focused DNS server written in Rust. Supports recursive resolution, authoritative serving, DNS-over-TLS, DNSSEC validation, and RPZ filtering. **~640K cached queries per second** — on par with a fully multi-threaded Unbound 1.19 on identical hardware, and faster at low-to-moderate concurrency.

**Project site:** https://zerosandonesllc.github.io/rDNS/ — features, benchmarks, install guides, and use cases.

## Features

- **Recursive Resolver** — Full iterative resolution from root hints with CNAME chain following
- **Forwarder Mode** — Forward queries to upstream resolvers (Cloudflare, Google, etc.)
- **Authoritative Server** — Serve zones from RFC 1035 zone files or PostgreSQL
- **DNS-over-TLS** — RFC 7858 encrypted DNS on port 853 via rustls
- **DNSSEC Validation** — Chain of trust verification from root trust anchors
- **RPZ Filtering** — Block/redirect domains via Response Policy Zones
- **Sharded Cache** — Concurrent cache with TTL eviction, negative caching, configurable bounds
- **Control Interface** — Unix socket control with `rdns-control` CLI
- **Prometheus Metrics** — `/metrics` endpoint for monitoring
- **Security Hardening** — Privilege dropping, FreeBSD Capsicum, PID file management
- **Cross-Platform** — FreeBSD, Linux, macOS
- **Single Binary** — Mode determined by config, not compile flags

## Performance

Benchmarked against **fully multi-threaded** Unbound 1.19 (`num-threads: 24`, `so-reuseport`) on identical hardware — 24-core AMD64, 100-query cached workload over UDP, `dnsperf`, medians of 3 runs, zero packet loss on both. rDNS peaks around **640K queries per second** and tracks Unbound closely across the concurrency range: ahead at low concurrency, roughly level in the middle, a little behind at very high concurrency.

| Concurrency | rDNS QPS | rDNS latency | Unbound QPS | Unbound latency | Ratio |
|------------:|---------:|-------------:|------------:|----------------:|------:|
| 50 clients  | 639,581  | 98 µs        | 596,564     | 76 µs           | 1.07× |
| 100 clients | 621,983  | 110 µs       | 621,024     | 70 µs           | 1.00× |
| 200 clients | 605,527  | 107 µs       | 615,914     | 74 µs           | 0.98× |
| 500 clients | 565,544  | 116 µs       | 609,617     | 79 µs           | 0.93× |

Unbound keeps a latency edge (~75 µs vs ~110 µs); rDNS holds a throughput edge at lower concurrency. Earlier releases published far higher multipliers, but those compared against a **single-threaded** Unbound — this table is the honest all-cores-vs-all-cores result. A profiling-driven optimization round ([#86](https://github.com/ZerosAndOnesLLC/rDNS/issues/86)) cut ~33% of per-query CPU (allocation + hashing) to close the gap.

Reproduce with `bench/throughput.sh` (peak throughput) or `bench/run.sh` (latency under sustained load). Full methodology, the optimization journey, and single-client figures in [BENCHMARKS.md](BENCHMARKS.md).

## Quick Start

```bash
# Build
cargo build --release

# With PostgreSQL support
cargo build --release --features postgres

# Run with config
./target/release/rdns -c rdns.toml.example

# Validate config
./target/release/rdns -c rdns.toml --check-config

# Control
./target/release/rdns-control stats
./target/release/rdns-control flush-cache
./target/release/rdns-control flush-name example.com
```

## Configuration

rDNS uses TOML for server configuration. See `rdns.toml.example` for all options.

### Resolver / Forwarder

```toml
[server]
mode = "resolver"

[resolver]
forwarders = ["1.1.1.1", "8.8.8.8"]
```

### Authoritative (Zone Files)

```toml
[server]
mode = "authoritative"

[authoritative]
source = "zone-files"
directory = "/etc/rdns/zones"
```

### Both (Recursive + Authoritative)

```toml
[server]
mode = "both"

[authoritative]
source = "zone-files"
directory = "/etc/rdns/zones"
```

### PostgreSQL Backend (ISP/Enterprise)

```toml
[server]
mode = "both"

[authoritative]
source = "database"

[authoritative.database]
connection = "postgresql://rdns:password@localhost:5432/rdns"
```

## Deployment

### systemd (Linux)

```bash
cp dist/rdns.service /etc/systemd/system/
systemctl enable rdns
systemctl start rdns
```

### rc.d (FreeBSD)

```bash
cp dist/rdns.rc /usr/local/etc/rc.d/rdns
chmod +x /usr/local/etc/rc.d/rdns
sysrc rdns_enable=YES
service rdns start
```

### Docker

```bash
docker build -t rdns .
docker run -p 53:53/udp -p 53:53/tcp -v /etc/rdns:/etc/rdns rdns
```

## Architecture

```
Client → UDP/TCP/TLS Listener → Query Router
                                    ├── RPZ Check (block/redirect)
                                    ├── Auth Engine (zone lookup)
                                    └── Recursive Resolver (cache → iterate)
```

- **Tokio async** multi-threaded runtime
- **DashMap** sharded concurrent cache
- **rustls** for TLS (no OpenSSL dependency)
- Zone data held in memory, loaded from files or PostgreSQL
- PostgreSQL LISTEN/NOTIFY for real-time zone reload

## AiFw HA Integration

When AiFw is deployed in active-passive cluster mode, a CARP virtual IP floats between
nodes. LAN clients that use the AiFw box as their DNS resolver should point at the CARP
VIP rather than a physical interface IP so that DNS resolution continues transparently
after failover.

### Bind to wildcard (recommended)

rDNS's default config already uses wildcard addresses:

```toml
[listeners]
udp = ["0.0.0.0:53", "[::]:53"]
tcp = ["0.0.0.0:53", "[::]:53"]
```

With this configuration, rDNS on the new CARP master accepts queries arriving at the
VIP immediately after failover — no rDNS configuration change is required.

**Verify your deployment uses wildcard listeners.** If your config specifies a
physical interface IP (e.g. `udp = ["192.168.1.1:53"]`), rDNS on the new master
will not respond to queries directed at the CARP VIP until you update the listen
address and reload.

### Multi-address listen (if IP-specific binding is required)

If you need rDNS bound to a specific interface IP and also the CARP VIP, list both:

```toml
[listeners]
udp = ["192.168.1.1:53", "192.168.1.254:53"]   # physical + CARP VIP
tcp = ["192.168.1.1:53", "192.168.1.254:53"]
```

rDNS iterates the list and spawns one listener task per address, so both are served
simultaneously.

### Failover behavior

On CARP failover the new master's rDNS process is already running with the CARP VIP
in its listener list (or on `0.0.0.0`). Because rDNS's cache is local to each node,
clients may see a brief increase in resolver latency on the first query after failover
(cache miss to upstream), then resume normal cached performance.

## License

MIT
