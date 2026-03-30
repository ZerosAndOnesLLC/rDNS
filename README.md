# rDNS

A high-performance, security-focused DNS server written in Rust. Supports recursive resolution, authoritative serving, DNS-over-TLS, DNSSEC validation, and RPZ filtering.

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

## License

MIT
