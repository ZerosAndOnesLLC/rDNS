---
layout: page
title: Benchmarks
heading: ~640,000 cached queries per second. On par with multi-threaded Unbound.
eyebrow: Benchmarks
lede: rDNS measured against a fully multi-threaded Unbound 1.19 on the same hardware, with the same workload, using dnsperf. All cores vs all cores — everything is reproducible.
description: rDNS benchmarks — ~640K cached QPS, at parity with multi-threaded Unbound 1.19 (ahead at low concurrency). Full methodology, test environment, and reproduction commands.
---

<section class="section">
  <div class="container">

    <h2>Head-to-head: queries per second</h2>
    <p>Cached query throughput, 10-second runs, medians of 3. Both servers on all 24 cores. Zero packet loss on both.</p>

    <div class="bench-chart">
      <div class="bench-row rdns">
        <span class="label">rDNS, 50 clients</span>
        <div class="track"><div class="bar" data-pct="100"></div></div>
        <span class="value">639,581</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 50</span>
        <div class="track"><div class="bar" data-pct="93"></div></div>
        <span class="value">596,564</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 100</span>
        <div class="track"><div class="bar" data-pct="97"></div></div>
        <span class="value">621,983</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 100</span>
        <div class="track"><div class="bar" data-pct="97"></div></div>
        <span class="value">621,024</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 200</span>
        <div class="track"><div class="bar" data-pct="95"></div></div>
        <span class="value">605,527</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 200</span>
        <div class="track"><div class="bar" data-pct="96"></div></div>
        <span class="value">615,914</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 500</span>
        <div class="track"><div class="bar" data-pct="88"></div></div>
        <span class="value">565,544</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 500</span>
        <div class="track"><div class="bar" data-pct="95"></div></div>
        <span class="value">609,617</span>
      </div>
    </div>

    <h2>Average latency</h2>
    <p>Under peak load, Unbound holds a latency edge; rDNS's advantage is single-client latency (see notes).</p>
    <div class="compare-table-wrap">
      <table class="compare-table">
        <thead>
          <tr><th>Clients</th><th>rDNS</th><th>Unbound</th></tr>
        </thead>
        <tbody>
          <tr><td>50</td><td>98 µs</td><td>76 µs</td></tr>
          <tr><td>100</td><td>110 µs</td><td>70 µs</td></tr>
          <tr><td>200</td><td>107 µs</td><td>74 µs</td></tr>
          <tr><td>500</td><td>116 µs</td><td>79 µs</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<section class="section">
  <div class="container">
    <h2>Test environment</h2>
    <div class="compare-table-wrap">
      <table class="compare-table">
        <tbody>
          <tr><th>CPU</th><td>24 cores (AMD64)</td></tr>
          <tr><th>RAM</th><td>32 GB</td></tr>
          <tr><th>OS</th><td>Linux 6.6.87 (WSL2)</td></tr>
          <tr><th>rDNS</th><td>v1.17.17, release build (LTO fat, codegen-units=1, target-cpu=native)</td></tr>
          <tr><th>Unbound</th><td>1.19, num-threads: 24, so-reuseport: yes, module-config: iterator</td></tr>
          <tr><th>Workload</th><td>100 unique queries (A, AAAA, MX, NS, TXT, NXDOMAIN), all cached</td></tr>
          <tr><th>Tool</th><td><code>dnsperf</code>, 12 sender threads, 10s runs, medians of 3</td></tr>
        </tbody>
      </table>
    </div>
    <p>Both servers configured as forwarders to 1.1.1.1 with DNSSEC disabled, logging at error-only level.</p>
  </div>
</section>

<section class="section">
  <div class="container">
    <h2>The optimization journey</h2>
    <p>rDNS started at 29,630 QPS and reached 437,434 across five rounds, then a sixth <a href="https://github.com/ZerosAndOnesLLC/rDNS/issues/86">profiling round</a> took it to ~640,000. That sixth round is the most instructive: a fair benchmark against multi-threaded Unbound showed rDNS behind, and <code>perf</code> traced ~33% of per-query CPU to allocation and SipHash. Each round is a learning artifact for any high-performance Rust networking work.</p>

    <h3>v6: kill per-query allocation and hashing (+22%)</h3>
    <p>Cache hits were paying for a throwaway <code>Vec&lt;String&gt;</code> per name-compression probe, a double SipHash on every cache key, a deep clone of the whole cache entry, and a full re-encode (with fresh compression) of a response that never changes.</p>
    <p><strong>Fix:</strong> borrow instead of allocating in the compression probe; a small inline FxHash for the cache and compression map (hashing the shard key once); <code>Arc</code>-shared cache entries; and — the biggest win — precompute each response's wire body once and memoize it on the entry, so hits just copy it and patch the TTL fields. Byte-identical output; retuned the recv-worker count too.</p>

    <h3>v1 → v2: Concurrency (+216%)</h3>
    <p>The original UDP listener processed queries sequentially. Each query blocked the socket while waiting for upstream resolution.</p>
    <p><strong>Fix:</strong> Spawn a Tokio task per incoming query. Forwarder connection pool multiplexes queries over one connected UDP socket with oneshot-channel response dispatch.</p>

    <h3>v2 → v3: Reduce allocations (−9%, better scaling)</h3>
    <p>Spawning a task per query added clone overhead and full <code>Message::decode → encode</code> round trips.</p>
    <p><strong>Fix:</strong> Sync fast-path for cache hits, authoritative answers, and RPZ blocks — inline in the recv loop. Wire-format fast parser. Direct wire encode with TTL adjustment.</p>

    <h3>v3 → v4: Faster cache (+264%)</h3>
    <p>DashMap's coarse sharding and <code>get_mut</code> write-lock-on-hit became the bottleneck.</p>
    <p><strong>Fix:</strong> Custom 256-shard cache on <code>parking_lot::RwLock</code>. Cache hits take read locks only. LTO fat, single codegen unit, target-cpu native in the release profile.</p>

    <h3>v4 → v5: Eliminate socket contention (+41%)</h3>
    <p>Multiple workers sharing one socket caused kernel-level race on the receive buffer.</p>
    <p><strong>Fix:</strong> <code>SO_REUSEPORT</code> — separate socket per worker on the same port. Kernel distributes packets by flow hash. <code>SO_RCVBUF</code> increased to 4 MB.</p>
  </div>
</section>

<section class="section">
  <div class="container">
    <h2>Reproduce it</h2>
    <pre><code># Build with native CPU optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Install tools
sudo apt-get install -y dnsperf unbound

# Run the benchmark suite
bash bench/run.sh

# Or manually:
./target/release/rdns -c bench/rdns-bench.toml &
dnsperf -s 127.0.0.1 -p 5553 -d bench/queryfile.txt -c 50 -l 10 -Q 500000</code></pre>

    <h3>Notes</h3>
    <ul>
      <li>Unbound runs multi-threaded (<code>num-threads: 24</code>, <code>so-reuseport: yes</code>) — a fair all-cores-vs-all-cores test. Earlier revisions compared against single-threaded Unbound and are superseded by these numbers.</li>
      <li>Single-client throughput is lower than Unbound because <code>SO_REUSEPORT</code> distributes by flow hash — one source, one worker. Not a realistic production scenario, but it means single-client latency stays very low.</li>
      <li>Medians of 3 runs with a co-located load generator, so ±5–10% variance is expected — read the result as parity, not a precise multiplier.</li>
      <li>These benchmarks measure cached query throughput only. Cold-cache depends on upstream latency.</li>
      <li>Results vary by hardware, kernel, and system load.</li>
    </ul>
  </div>
</section>

{% include cta.html %}
