---
layout: page
title: Benchmarks
heading: 437,434 queries per second. 32 microsecond latency.
eyebrow: Benchmarks
lede: rDNS measured against Unbound 1.19.2 on the same hardware, with the same workload, using dnsperf 2.14. Everything is reproducible.
description: rDNS benchmarks — 437K QPS, 32µs latency, 1.3-1.5x faster than Unbound 1.19. Full methodology, test environment, and reproduction commands.
---

<section class="section">
  <div class="container">

    <h2>Head-to-head: queries per second</h2>
    <p>Cached query throughput, 10-second runs at a 500 K QPS cap.</p>

    <div class="bench-chart">
      <div class="bench-row rdns">
        <span class="label">rDNS, 10 clients</span>
        <div class="track"><div class="bar" data-pct="92"></div></div>
        <span class="value">401,752</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 10</span>
        <div class="track"><div class="bar" data-pct="60"></div></div>
        <span class="value">262,187</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 50</span>
        <div class="track"><div class="bar" data-pct="100"></div></div>
        <span class="value">437,434</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 50</span>
        <div class="track"><div class="bar" data-pct="77"></div></div>
        <span class="value">335,813</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 100</span>
        <div class="track"><div class="bar" data-pct="75"></div></div>
        <span class="value">328,340</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 100</span>
        <div class="track"><div class="bar" data-pct="79"></div></div>
        <span class="value">346,334</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 200</span>
        <div class="track"><div class="bar" data-pct="86"></div></div>
        <span class="value">375,192</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 200</span>
        <div class="track"><div class="bar" data-pct="60"></div></div>
        <span class="value">263,109</span>
      </div>

      <div class="bench-row rdns">
        <span class="label">rDNS, 500</span>
        <div class="track"><div class="bar" data-pct="100"></div></div>
        <span class="value">437,365</span>
      </div>
      <div class="bench-row unbound">
        <span class="label">Unbound, 500</span>
        <div class="track"><div class="bar" data-pct="75"></div></div>
        <span class="value">328,564</span>
      </div>
    </div>

    <h2>Average latency</h2>
    <div class="compare-table-wrap">
      <table class="compare-table">
        <thead>
          <tr><th>Clients</th><th>rDNS</th><th>Unbound</th><th>Speedup</th></tr>
        </thead>
        <tbody>
          <tr><td>10</td><td>34 µs</td><td>317 µs</td><td class="yes">9.3×</td></tr>
          <tr><td>50</td><td>32 µs</td><td>248 µs</td><td class="yes">7.8×</td></tr>
          <tr><td>100</td><td>59 µs</td><td>230 µs</td><td class="yes">3.9×</td></tr>
          <tr><td>200</td><td>57 µs</td><td>302 µs</td><td class="yes">5.3×</td></tr>
          <tr><td>500</td><td>53 µs</td><td>237 µs</td><td class="yes">4.5×</td></tr>
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
          <tr><th>rDNS</th><td>v1.5.0, release build (LTO fat, codegen-units=1, target-cpu=native)</td></tr>
          <tr><th>Unbound</th><td>1.19.2-1ubuntu3.7, single-threaded, module-config: iterator</td></tr>
          <tr><th>Workload</th><td>100 unique queries (A, AAAA, MX, NS, TXT, NXDOMAIN), all cached</td></tr>
          <tr><th>Tool</th><td><code>dnsperf -l 10 -Q 500000</code></td></tr>
        </tbody>
      </table>
    </div>
    <p>Both servers configured as forwarders to 1.1.1.1 with DNSSEC disabled, logging at error-only level.</p>
  </div>
</section>

<section class="section">
  <div class="container">
    <h2>The optimization journey</h2>
    <p>rDNS started at 29,630 QPS and ended at 437,434 — a 14.8× improvement across five rounds. Each one is a learning artifact for any high-performance Rust networking work.</p>

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
      <li>Single-client performance is lower than Unbound because <code>SO_REUSEPORT</code> distributes by flow hash — one source, one worker. Not a realistic production scenario.</li>
      <li>Unbound was tested with <code>num-threads: 1</code> (its default for benchmarking).</li>
      <li>These benchmarks measure cached query throughput only. Cold-cache depends on upstream latency.</li>
      <li>Results vary by hardware, kernel, and system load.</li>
    </ul>
  </div>
</section>

{% include cta.html %}
