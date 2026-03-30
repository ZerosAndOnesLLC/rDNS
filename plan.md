# rDNS — Rust DNS Server Architecture Plan

A high-performance, security-focused DNS server written in Rust. Supports recursive resolution, authoritative serving, DNS-over-TLS, DNSSEC validation, and RPZ filtering. Cross-platform (FreeBSD + Linux), scales from home use to ISP/enterprise.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        rDNS Server                          │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ UDP/TCP  │  │ DNS-over- │  │ Control  │  │Prometheus │  │
│  │ Listener │  │   TLS     │  │  Socket  │  │ /metrics  │  │
│  │ :53      │  │  :853     │  │  (unix)  │  │ :9153     │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───────────┘  │
│       │              │             │                         │
│       └──────┬───────┘             │                         │
│              ▼                     ▼                         │
│  ┌───────────────────┐  ┌──────────────────┐               │
│  │   Query Router    │  │  Control Handler │               │
│  │  (auth/recurse?)  │  │  (reload/flush)  │               │
│  └─────┬───────┬─────┘  └──────────────────┘               │
│        │       │                                            │
│   ┌────▼──┐ ┌──▼──────────┐                                │
│   │ Auth  │ │  Recursive   │                                │
│   │Engine │ │  Resolver    │                                │
│   └───┬───┘ └──────┬──────┘                                │
│       │            │                                        │
│  ┌────▼────────────▼────┐                                  │
│  │   Response Cache     │                                  │
│  │  (sharded, TTL-based)│                                  │
│  └──────────────────────┘                                  │
│                                                             │
│  ┌──────────────────────┐  ┌───────────────┐               │
│  │   Zone Store         │  │  RPZ Engine   │               │
│  │  (memory-resident)   │  │  (filter)     │               │
│  └─────┬──────┬─────────┘  └───────────────┘               │
│        │      │                                             │
│   ┌────▼──┐ ┌─▼──────────┐                                │
│   │ Zone  │ │ PostgreSQL  │                                │
│   │ Files │ │ (optional)  │                                │
│   └───────┘ └─────────────┘                                │
└─────────────────────────────────────────────────────────────┘
```

## Core Design Decisions

- **Async runtime**: Tokio multi-threaded
- **Cache**: Sharded concurrent hashmap (dashmap or custom), TTL-evicted
- **Zone storage**: In-memory tree, loaded from zone files or PostgreSQL
- **Config**: TOML (server config), RFC 1035 zone files (zone data)
- **Control**: Unix domain socket + `rdns-control` CLI tool
- **Metrics**: Prometheus HTTP endpoint on configurable port
- **Security**: Privilege drop after bind, Capsicum on FreeBSD, DNSSEC validation
- **License**: MIT

## Crate Dependencies (planned)

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `tokio-rustls` / `rustls` | TLS (no OpenSSL dependency) |
| `bytes` | Efficient buffer management |
| `dashmap` | Sharded concurrent hashmap for cache |
| `serde` / `toml` | Config parsing |
| `tracing` | Structured logging |
| `metrics` + `metrics-exporter-prometheus` | Prometheus metrics |
| `sqlx` | PostgreSQL (optional feature) |
| `ring` | Crypto for DNSSEC |
| `clap` | CLI argument parsing |
| `nix` | Unix privilege dropping, socket control |
| `capsicum` | FreeBSD Capsicum sandboxing (conditional) |

## Project Structure

```
rdns/
├── Cargo.toml
├── Cargo.lock
├── rdns.toml.example          # Example config
├── src/
│   ├── main.rs                # Entry point, signal handling
│   ├── config.rs              # TOML config parsing
│   ├── server.rs              # Server orchestration
│   ├── listener/
│   │   ├── mod.rs
│   │   ├── udp.rs             # UDP listener
│   │   ├── tcp.rs             # TCP listener
│   │   └── tls.rs             # DNS-over-TLS listener
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── header.rs          # DNS header parsing
│   │   ├── message.rs         # Full message encode/decode
│   │   ├── name.rs            # Domain name compression
│   │   ├── record.rs          # Resource record types
│   │   ├── rdata.rs           # RDATA parsing per type
│   │   ├── opcode.rs          # DNS opcodes
│   │   └── rcode.rs           # Response codes
│   ├── resolver/
│   │   ├── mod.rs
│   │   ├── recursive.rs       # Recursive resolution engine
│   │   ├── forwarder.rs       # Forwarding mode
│   │   └── iterator.rs        # Iterative query logic
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── engine.rs          # Authoritative lookup engine
│   │   ├── zone.rs            # Zone data structures
│   │   ├── zone_tree.rs       # In-memory zone tree
│   │   ├── zone_parser.rs     # RFC 1035 zone file parser
│   │   └── catalog.rs         # Zone catalog (manages all zones)
│   ├── cache/
│   │   ├── mod.rs
│   │   ├── entry.rs           # Cache entry with TTL
│   │   └── store.rs           # Sharded cache store
│   ├── dnssec/
│   │   ├── mod.rs
│   │   ├── validator.rs       # DNSSEC chain validation
│   │   ├── algorithms.rs      # Signing algorithm support
│   │   └── trust_anchor.rs    # Root trust anchors
│   ├── rpz/
│   │   ├── mod.rs
│   │   ├── engine.rs          # RPZ matching engine
│   │   └── policy.rs          # Policy actions
│   ├── control/
│   │   ├── mod.rs
│   │   └── handler.rs         # Unix socket command handler
│   ├── metrics.rs             # Prometheus metrics
│   └── security/
│       ├── mod.rs
│       ├── privilege.rs       # Privilege dropping
│       └── sandbox.rs         # Capsicum / platform sandboxing
├── src/bin/
│   └── rdns-control.rs        # Control CLI binary
├── tests/
│   ├── protocol_tests.rs
│   ├── cache_tests.rs
│   ├── resolver_tests.rs
│   └── auth_tests.rs
└── zones/
    └── example.com.zone       # Example zone file
```

## Implementation Phases

### Phase 1: Foundation — Protocol & Transport
> Goal: Parse and respond to DNS queries over UDP/TCP

- [x] 1.1 — Project scaffold (Cargo.toml, module structure, config skeleton)
- [x] 1.2 — DNS protocol wire format (header, message, name compression, encode/decode)
- [x] 1.3 — Resource record types (A, AAAA, NS, CNAME, MX, TXT, SOA, PTR, SRV, CAA)
- [x] 1.4 — UDP listener (bind :53, receive query, parse, echo back SERVFAIL)
- [x] 1.5 — TCP listener (length-prefixed framing, same query handling)
- [x] 1.6 — Unit tests for protocol parsing (known-good packets)

### Phase 2: Caching Layer
> Goal: Sharded concurrent cache with TTL eviction

- [ ] 2.1 — Cache entry struct (response data, TTL, insertion time, access count)
- [ ] 2.2 — Sharded cache store (dashmap-based, configurable size)
- [ ] 2.3 — TTL expiration (background sweep task, lazy eviction on access)
- [ ] 2.4 — Cache lookup integration with listeners (check cache before processing)
- [ ] 2.5 — Negative caching (NXDOMAIN, NODATA per RFC 2308)
- [ ] 2.6 — Cache tests

### Phase 3: Recursive Resolver
> Goal: Full recursive resolution from root hints

- [ ] 3.1 — Root hints loader (built-in root server addresses)
- [ ] 3.2 — Iterative resolution engine (follow referrals from root → TLD → auth)
- [ ] 3.3 — CNAME/DNAME chain following
- [ ] 3.4 — Forwarder mode (forward to upstream resolvers, cache responses)
- [ ] 3.5 — Query deduplication (coalesce identical in-flight queries)
- [ ] 3.6 — Retry logic with timeout (configurable per-server timeout, fallback)
- [ ] 3.7 — Resolver integration tests

### Phase 4: Authoritative Engine
> Goal: Serve zones from zone files loaded into memory

- [ ] 4.1 — Zone data structures (zone tree, node, RRset)
- [ ] 4.2 — RFC 1035 zone file parser ($ORIGIN, $TTL, $INCLUDE, RR entries)
- [ ] 4.3 — Zone catalog (load/reload/remove zones)
- [ ] 4.4 — Authoritative query engine (exact match, wildcard, delegation, NXDOMAIN)
- [ ] 4.5 — Query router (determine if query is auth or recursive, route accordingly)
- [ ] 4.6 — AXFR/IXFR zone transfer (secondary support)
- [ ] 4.7 — NOTIFY handling (trigger reload on primary change)
- [ ] 4.8 — Authoritative tests with sample zones

### Phase 5: DNSSEC Validation
> Goal: Full DNSSEC validation for recursive responses

- [ ] 5.1 — Trust anchor management (built-in root KSK, RFC 5011 auto-update)
- [ ] 5.2 — DS/DNSKEY/RRSIG record parsing and wire format
- [ ] 5.3 — Signature validation (RSA/SHA-256, ECDSA P-256, Ed25519)
- [ ] 5.4 — Chain of trust validation (root → TLD → zone)
- [ ] 5.5 — NSEC/NSEC3 denial of existence validation
- [ ] 5.6 — Set CD/AD bits correctly in responses
- [ ] 5.7 — DNSSEC tests with known-good and known-bad chains

### Phase 6: DNS-over-TLS
> Goal: Serve DNS queries over TLS (RFC 7858)

- [ ] 6.1 — TLS listener on :853 (rustls, configurable cert/key)
- [ ] 6.2 — Connection handling (persistent connections, idle timeout)
- [ ] 6.3 — Upstream DoT support (resolver can query upstream over TLS)
- [ ] 6.4 — TLS session resumption for performance
- [ ] 6.5 — TLS integration tests

### Phase 7: RPZ (Response Policy Zones)
> Goal: Filter/block queries based on RPZ rules

- [ ] 7.1 — RPZ zone parser (load RPZ zone files)
- [ ] 7.2 — RPZ matching engine (qname, IP, nsdname triggers)
- [ ] 7.3 — Policy actions (NXDOMAIN, NODATA, passthru, local-data, redirect)
- [ ] 7.4 — RPZ zone refresh (periodic re-fetch via AXFR/HTTP)
- [ ] 7.5 — RPZ tests

### Phase 8: Control Interface & Metrics
> Goal: Runtime management and observability

- [ ] 8.1 — Unix domain socket listener for control commands
- [ ] 8.2 — Control protocol (simple text commands: stats, flush, reload, dump)
- [ ] 8.3 — `rdns-control` CLI binary
- [ ] 8.4 — Prometheus metrics endpoint (/metrics on configurable port)
- [ ] 8.5 — Key metrics: QPS, cache hit/miss ratio, latency histograms, upstream errors
- [ ] 8.6 — Structured logging with tracing (JSON + syslog output)

### Phase 9: Security Hardening
> Goal: Privilege separation and platform sandboxing

- [ ] 9.1 — Privilege dropping (bind ports as root, drop to rdns user)
- [ ] 9.2 — FreeBSD Capsicum sandboxing (enter capability mode after init)
- [ ] 9.3 — Linux seccomp-bpf filtering (restrict syscalls)
- [ ] 9.4 — Chroot / filesystem isolation
- [ ] 9.5 — Source port randomization + 0x20 encoding (anti-spoofing)
- [ ] 9.6 — Rate limiting (per-source query rate limits)

### Phase 10: PostgreSQL Backend
> Goal: Database-backed zone storage for large-scale deployments

- [ ] 10.1 — Database schema (zones, records, metadata tables)
- [ ] 10.2 — SQLx integration (connection pool, async queries)
- [ ] 10.3 — Zone loader from DB (startup full load, single-zone reload)
- [ ] 10.4 — Postgres LISTEN/NOTIFY for change detection
- [ ] 10.5 — Migration tooling (sqlx migrations)
- [ ] 10.6 — DB backend tests

### Phase 11: Packaging & Distribution
> Goal: Ready for production deployment

- [ ] 11.1 — FreeBSD rc.d service script
- [ ] 11.2 — Linux systemd unit file
- [ ] 11.3 — FreeBSD port Makefile
- [ ] 11.4 — Docker image
- [ ] 11.5 — Man pages (rdns.8, rdns-control.8, rdns.toml.5)
- [ ] 11.6 — Performance benchmarks (dnsperf / queryperf)
- [ ] 11.7 — README with quick-start guide

## Config Example (rdns.toml)

```toml
[server]
# "resolver" | "authoritative" | "both"
mode = "both"
user = "rdns"
group = "rdns"
pidfile = "/var/run/rdns/rdns.pid"

[listeners]
# Plain DNS
udp = ["0.0.0.0:53", "[::]:53"]
tcp = ["0.0.0.0:53", "[::]:53"]

# DNS-over-TLS
[listeners.tls]
addresses = ["0.0.0.0:853", "[::]:853"]
cert = "/etc/rdns/tls/cert.pem"
key = "/etc/rdns/tls/key.pem"

[cache]
max_entries = 1_000_000
max_ttl = 86400        # cap TTL at 24h
min_ttl = 60           # floor TTL at 60s
negative_ttl = 300     # NXDOMAIN cache time

[resolver]
# Empty = full recursive from root hints
forwarders = []
# forwarders = ["1.1.1.1:853@tls", "8.8.8.8"]
dnssec = true
qname_minimization = true
max_recursion_depth = 30

[authoritative]
# "zone-files" | "database" | "none"
source = "zone-files"
directory = "/etc/rdns/zones"

# [authoritative.database]
# connection = "postgresql://rdns:password@localhost:5432/rdns"

[rpz]
zones = [
    { name = "rpz.example.com", file = "/etc/rdns/rpz/blocklist.rpz" },
]

[control]
socket = "/var/run/rdns/control.sock"

[metrics]
enabled = true
address = "127.0.0.1:9153"

[logging]
level = "info"         # trace, debug, info, warn, error
format = "json"        # "json" | "syslog" | "text"

[security]
sandbox = true         # Capsicum on FreeBSD, seccomp on Linux
rate_limit = 1000      # queries per second per source IP
```
