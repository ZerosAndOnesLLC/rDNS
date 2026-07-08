# rDNS

[![Latest release](https://img.shields.io/github/v/release/ZerosAndOnesLLC/rDNS?label=release&color=blue)](https://github.com/ZerosAndOnesLLC/rDNS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-ce4218?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20FreeBSD%20%7C%20macOS-informational)](#deployment)
[![Performance](https://img.shields.io/badge/perf-570K%20QPS%20%2F%20130%C2%B5s-success)](https://zerosandonesllc.github.io/rDNS/benchmarks/)

A high-performance, security-focused DNS server written in Rust. Supports recursive resolution, authoritative serving, DNS-over-TLS, DNSSEC validation, and RPZ filtering. **570K queries per second at ~130 µs under peak load** — 2.5–2.9× faster than Unbound on identical hardware.

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

Benchmarked against Unbound 1.19 on identical hardware (24-core AMD64, 100-query cached workload over UDP, `dnsperf`). rDNS sustains **570K queries per second** with flat ~130 µs average latency and zero packet loss as concurrency scales — 2.5–2.9× Unbound's throughput.

| Concurrency | rDNS QPS | rDNS latency | Unbound QPS | Speedup |
|------------:|---------:|-------------:|------------:|--------:|
| 50 clients  | 570,188  | 133 µs       | 194,456     | 2.93×   |
| 100 clients | 557,947  | 136 µs       | 195,668     | 2.85×   |
| 200 clients | 547,489  | 137 µs       | 204,063     | 2.68×   |
| 500 clients | 557,150  | 125 µs       | 223,277     | 2.50×   |

Reproduce with `bench/throughput.sh` (peak throughput) or `bench/run.sh` (latency under sustained load). Full methodology and single-client latency figures in [BENCHMARKS.md](BENCHMARKS.md).

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
