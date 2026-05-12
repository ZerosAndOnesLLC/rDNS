---
layout: page
title: Features
heading: Everything a modern DNS server needs.
eyebrow: Features
lede: From a homelab resolver to an ISP-scale authoritative cluster — rDNS covers it in one binary.
description: rDNS features — recursive resolver, authoritative server, DNS-over-TLS, DNSSEC validation, RPZ filtering, sharded cache, Prometheus metrics, FreeBSD Capsicum sandbox.
---

<section class="section">
  <div class="container">

  <div class="split-row">
    <div>
      <h2>{% include icons/globe.svg %} Recursive resolver</h2>
      <p>Full iterative resolution from root hints. CNAME chain following with loop detection. Configurable recursion depth. QNAME minimization (RFC 9156) is on by default.</p>
      <p>Optionally run as a forwarder to upstream resolvers (Cloudflare, Google, Quad9) — same binary, configuration-driven.</p>
    </div>
    <pre><code>[resolver]
forwarders = []
dnssec = true
qname_minimization = true
max_recursion_depth = 30</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/server.svg %} Authoritative server</h2>
      <p>Serve zones from RFC 1035 zone files, or from a PostgreSQL backend for ISP/enterprise scale. PostgreSQL <code>LISTEN/NOTIFY</code> drives hot zone reloads without restart.</p>
      <p>Run authoritative-only, recursive-only, or both in the same process.</p>
    </div>
    <pre><code>[authoritative]
source = "database"

[authoritative.database]
connection = "postgresql://rdns:..."</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/lock.svg %} DNS-over-TLS</h2>
      <p>RFC 7858 encrypted DNS on port 853. TLS provided by rustls — no OpenSSL in the binary, no OpenSSL CVEs to track.</p>
    </div>
    <pre><code>[listeners.tls]
addresses = ["0.0.0.0:853"]
cert = "/etc/rdns/tls/cert.pem"
key  = "/etc/rdns/tls/key.pem"</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/shield.svg %} DNSSEC validation</h2>
      <p>Chain of trust verification from root trust anchors. Disable per-query if needed; validated by default.</p>
    </div>
    <pre><code>[resolver]
dnssec = true</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/filter.svg %} RPZ filtering</h2>
      <p>Block or redirect domains via Response Policy Zones (BIND-compatible). Use for ad blocking, malware filtering, or parental controls.</p>
    </div>
    <pre><code>[[rpz.zones]]
name = "rpz.local"
file = "/etc/rdns/rpz/blocklist.rpz"</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/bolt.svg %} Sharded cache with serve-stale</h2>
      <p>256-shard concurrent cache built on <code>parking_lot::RwLock</code>. Cache hits take read locks only — no contention between workers. Negative caching, TTL bounds, and RFC 8767 serve-stale for graceful degradation during upstream outages.</p>
    </div>
    <pre><code>[cache]
max_entries = 1_000_000
serve_stale = true
stale_max_ttl = 86400
stale_answer_ttl = 30</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/terminal.svg %} Control CLI</h2>
      <p>Unix socket control interface. Flush the whole cache, flush a single name, dump stats — all without touching the running daemon's config.</p>
    </div>
    <pre><code>rdns-control stats
rdns-control flush-cache
rdns-control flush-name example.com</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/chart.svg %} Prometheus metrics</h2>
      <p>Per-listener QPS, cache hit rates, latency histograms, upstream resolution stats — all exposed at <code>/metrics</code> in Prometheus exposition format. Drop into your existing Grafana stack.</p>
    </div>
    <pre><code>[metrics]
enabled = true
address = "127.0.0.1:9153"</code></pre>
  </div>

  <div class="split-row">
    <div>
      <h2>{% include icons/database.svg %} Security hardening</h2>
      <p>Privilege dropping after bind. FreeBSD Capsicum capability sandbox. PID file management. Single-instance enforcement via filesystem lock. Rate limiting per source.</p>
    </div>
    <pre><code>[security]
sandbox = true
rate_limit = 1000

[server]
user  = "rdns"
group = "rdns"</code></pre>
  </div>

  </div>
</section>

{% include cta.html %}
