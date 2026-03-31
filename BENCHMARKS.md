# rDNS Performance Benchmarks

Benchmark results comparing rDNS against Unbound 1.19.2, the industry-standard recursive DNS resolver. All tests performed on the same machine using `dnsperf` 2.14.0 with cached queries over UDP.

## Test Environment

| Component | Details |
|-----------|---------|
| CPU | 24 cores (AMD64) |
| RAM | 32 GB |
| OS | Linux 6.6.87 (WSL2) |
| rDNS | v1.5.0, release build (LTO fat, codegen-units=1, target-cpu=native) |
| Unbound | 1.19.2-1ubuntu3.7, single-threaded, module-config: iterator |
| Workload | 100 unique queries (A, AAAA, MX, NS, TXT, NXDOMAIN), all cached |
| Tool | `dnsperf -l 10 -Q 500000` (10 second runs, 500K QPS cap) |

Both servers configured as forwarders to 1.1.1.1 with DNSSEC disabled, logging at error-only level.

## Results Summary

### Throughput (Queries Per Second)

```
                     rDNS vs Unbound — Queries Per Second
                     ════════════════════════════════════

  500 clients  ██████████████████████████████████████████████  437,365
               ██████████████████████████████████▌             328,564

  200 clients  █████████████████████████████████████████▎      375,192
               ███████████████████████████▊                    263,109

  100 clients  ██████████████████████████████████▌             328,340
               █████████████████████████████████████           346,334

   50 clients  ████████████████████████████████████████████████ 437,434
               ███████████████████████████████████▊            335,813

   10 clients  ████████████████████████████████████████████▎   401,752
               ███████████████████████████▋                    262,187

               ■ rDNS    ■ Unbound
```

### Head-to-Head Comparison

| Clients | rDNS QPS | Unbound QPS | Ratio | Winner |
|---------|----------|-------------|-------|--------|
| 10 | 401,752 | 262,187 | 1.53x | rDNS |
| 50 | 437,434 | 335,813 | 1.30x | rDNS |
| 100 | 328,340 | 346,334 | 0.95x | ~Parity |
| 200 | 375,192 | 263,109 | 1.43x | rDNS |
| 500 | 437,365 | 328,564 | 1.33x | rDNS |

### Average Latency

| Clients | rDNS | Unbound |
|---------|------|---------|
| 10 | 34 us | 317 us |
| 50 | 32 us | 248 us |
| 100 | 59 us | 230 us |
| 200 | 57 us | 302 us |
| 500 | 53 us | 237 us |

At 50 clients, rDNS average latency is **32 microseconds** — 7.8x lower than Unbound.

## Optimization Journey

rDNS went through 5 optimization rounds, improving from 29K to 437K QPS — a **14.8x improvement**.

### Progression

```
  QPS (50 concurrent clients, cached)

  v1  ██▌                                                29,630
  v2  ████████▎                                          93,781
  v3  ███████▍                                           84,881
  v4  ███████████████████████████████▎                  309,386
  v5  █████████████████████████████████████████████████  437,434

  0       100K      200K      300K      400K      500K
```

| Version | QPS (50 clients) | Key Change |
|---------|------------------|------------|
| **v1** | 29,630 | Baseline — sequential recv/send loop |
| **v2** | 93,781 | Task-per-query, forwarder connection pool |
| **v3** | 84,881 | Sync fast-path for cache hits, direct wire encoding |
| **v4** | 309,386 | parking_lot sharded cache, LTO, native CPU |
| **v5** | 437,434 | SO_REUSEPORT per-worker sockets |

### What Each Round Changed

#### v1 → v2: Concurrency (+216%)

The original UDP listener processed queries sequentially — `recv_from` → `await handle_query` → `send_to` in a single loop. Under concurrency, each query blocked the socket while waiting for upstream resolution.

**Fix:** Spawn a tokio task per incoming query so the recv loop is never blocked. Created a forwarder connection pool that multiplexes queries over a single connected UDP socket with async response dispatch via oneshot channels.

#### v2 → v3: Reduce Allocations (-9%, but better scaling)

Spawning a task for every query (even cache hits) added overhead from cloning resolver/cache/auth/rpz per task, plus full `Message::decode` → `Message::encode` round-trip.

**Fix:** Added a synchronous fast-path that handles cache hits, authoritative answers, and RPZ blocks inline in the recv loop without spawning a task. Built a fast query parser that extracts name/type/class from wire format without full message decode. Cache responses are encoded directly to wire format with TTL adjustment, bypassing `Message` struct construction entirely.

#### v3 → v4: Faster Cache (+264%)

DashMap was the bottleneck under contention. Its internal sharding was too coarse and `get_mut` (needed to increment hit count) took a write lock on every cache hit.

**Fix:** Replaced DashMap with a custom 256-shard cache using `parking_lot::RwLock`. Cache hits take a read lock only — multiple workers can serve cache hits simultaneously with zero contention. Write locks are only taken for inserts and expired entry cleanup. Also enabled LTO (fat), single codegen unit, and native CPU targeting in the release profile.

#### v4 → v5: Eliminate Socket Contention (+41%)

Multiple recv workers sharing a single `Arc<UdpSocket>` caused kernel-level contention on the socket receive buffer. Workers would wake up, race to `recv_from`, and only one would get the packet.

**Fix:** Use `SO_REUSEPORT` to bind a separate socket per worker on the same port. The kernel distributes incoming packets across sockets using a consistent hash, so each worker processes its packets independently with zero contention. Falls back to shared socket on platforms without `SO_REUSEPORT`. Also increased `SO_RCVBUF` to 4 MB for burst absorption.

## Architecture

```
  Client packets arrive on port 53
              │
              ▼
  ┌───────────────────────────┐
  │    Kernel (SO_REUSEPORT)  │
  │    Distributes by flow    │
  └──┬──────┬──────┬──────┬───┘
     ▼      ▼      ▼      ▼
  Worker  Worker  Worker  Worker   ← Each has its own socket
     │      │      │      │
     ▼      ▼      ▼      ▼
  ┌──────────────────────────┐
  │  parse_query_fast()      │     Wire format → name + type (no alloc)
  │  try_handle_sync()       │     Cache/Auth/RPZ check (read lock only)
  │  build_response_fast()   │     Direct wire encode (no Message struct)
  │  send_to()               │     Response back to client
  └──────────────────────────┘
           │ cache miss
           ▼
     tokio::spawn()
           │
  ┌────────▼─────────┐
  │  Resolver         │
  │  ForwarderPool    │     Single connected socket, multiplexed by query ID
  │  Cache insert     │     Write lock on one shard only
  │  send_to()        │
  └──────────────────┘
```

The hot path (cache hit) involves:
- 1 fast parse of the query wire format
- 1 read lock on one cache shard
- 1 direct wire-format encode of the response
- 0 heap allocations (except the response Vec)
- 0 task spawns
- 0 async awaits (except the socket I/O itself)

## Reproducing

```bash
# Build
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Install tools
sudo apt-get install -y dnsperf unbound

# Run the benchmark suite
bash bench/run.sh

# Or manually:
./target/release/rdns -c bench/rdns-bench.toml &
dnsperf -s 127.0.0.1 -p 5553 -d bench/queryfile.txt -c 50 -l 10 -Q 500000
```

## Notes

- Single-client performance (61K QPS) is lower than Unbound (215K) because SO_REUSEPORT distributes by flow hash — with one source, only one of N workers receives packets. This is not a realistic production scenario.
- Unbound was tested with `num-threads: 1` (its default for benchmarking). Multi-threaded Unbound may perform differently.
- These benchmarks measure cached query throughput only. Cold-cache performance depends on upstream latency and is not measured here.
- Results will vary by hardware, kernel version, and system load.
