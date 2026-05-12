---
layout: page
title: Configuration
heading: Configuration reference.
eyebrow: Docs
lede: rDNS reads one TOML file. Here's every section, every option.
description: rDNS configuration reference — every TOML section, the rdns-control CLI, and the Prometheus metrics endpoint.
---

<section class="section">
  <div class="container">

    <h2><code>[server]</code></h2>
    <pre><code>[server]
mode = "resolver"        # "resolver" | "authoritative" | "both"
user = "rdns"
group = "rdns"
pidfile = "/var/run/rdns/rdns.pid"</code></pre>
    <p>Mode is config-driven — same binary, different behavior. User/group are dropped to after binding port 53.</p>

    <h2><code>[listeners]</code></h2>
    <pre><code>[listeners]
udp = ["0.0.0.0:53", "[::]:53"]
tcp = ["0.0.0.0:53", "[::]:53"]

[listeners.tls]
addresses = ["0.0.0.0:853", "[::]:853"]
cert = "/etc/rdns/tls/cert.pem"
key  = "/etc/rdns/tls/key.pem"</code></pre>
    <p>Each address in the list gets its own listener task. Use wildcard for HA (see <a href="{{ '/use-cases/' | relative_url }}">Use cases</a>).</p>

    <h2><code>[resolver]</code></h2>
    <pre><code>[resolver]
forwarders = []                  # empty = full recursive from root hints
dnssec = true
qname_minimization = true
max_recursion_depth = 30</code></pre>

    <h2><code>[authoritative]</code></h2>
    <pre><code>[authoritative]
source = "none"                  # "zone-files" | "database" | "none"
directory = "/etc/rdns/zones"

[authoritative.database]
connection = "postgresql://rdns:password@localhost:5432/rdns"</code></pre>
    <p>PostgreSQL backend requires building with <code>--features postgres</code>.</p>

    <h2><code>[cache]</code></h2>
    <pre><code>[cache]
max_entries = 1_000_000
max_ttl = 86400
min_ttl = 60
negative_ttl = 300
serve_stale = true
stale_max_ttl = 86400
stale_answer_ttl = 30</code></pre>
    <p>Serve-stale (RFC 8767) serves expired entries with a short TTL when upstream is down. Bounded by <code>stale_max_ttl</code>.</p>

    <h2><code>[rpz]</code></h2>
    <pre><code>[[rpz.zones]]
name = "rpz.adblock"
file = "/etc/rdns/rpz/blocklist.rpz"</code></pre>
    <p>BIND-compatible RPZ files. Multiple zones allowed; first match wins.</p>

    <h2><code>[control]</code></h2>
    <pre><code>[control]
socket = "/var/run/rdns/control.sock"</code></pre>

    <h2><code>[metrics]</code></h2>
    <pre><code>[metrics]
enabled = false
address = "127.0.0.1:9153"</code></pre>
    <p>Prometheus exposition format at <code>/metrics</code>.</p>

    <h2><code>[logging]</code></h2>
    <pre><code>[logging]
level = "info"      # error | warn | info | debug | trace
format = "json"     # json | text</code></pre>

    <h2><code>[security]</code></h2>
    <pre><code>[security]
sandbox = true       # enable Capsicum on FreeBSD
rate_limit = 1000    # max QPS per source IP</code></pre>

    <h2><code>[edns]</code></h2>
    <pre><code>[edns]
udp_payload_size = 1232</code></pre>
    <p>Follows DNS Flag Day 2020. Values below 512 are clamped per RFC 6891.</p>

    <h2>The <code>rdns-control</code> CLI</h2>
    <pre><code>rdns-control stats
rdns-control flush-cache
rdns-control flush-name example.com
rdns-control reload-zones</code></pre>

    <h2>Metrics endpoint</h2>
    <p>Sample output at <code>/metrics</code>:</p>
    <pre><code># HELP rdns_queries_total Total queries received
# TYPE rdns_queries_total counter
rdns_queries_total{listener="udp:0.0.0.0:53"} 1245678

# HELP rdns_cache_hits_total Cache hit count
# TYPE rdns_cache_hits_total counter
rdns_cache_hits_total 982341

# HELP rdns_query_duration_seconds Query handling latency
# TYPE rdns_query_duration_seconds histogram</code></pre>

    <p class="mt-lg">The <a href="https://github.com/{{ site.repository }}/blob/main/rdns.toml.example">rdns.toml.example</a> in the repo is the source of truth.</p>
  </div>
</section>

{% include cta.html %}
