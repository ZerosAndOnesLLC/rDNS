---
layout: page
title: Use cases
heading: Built for every scale, from homelab to ISP.
eyebrow: Use cases
lede: rDNS is one binary with one config file. The deployment shape is whatever you want it to be.
description: rDNS deployment recipes — self-hosted homelab resolver, network-wide ad blocking via RPZ, ISP-scale authoritative with PostgreSQL, and high-availability with CARP VIP.
---

<section class="section">
  <div class="container">
    <div class="use-case-grid">

      <div class="use-case">
        <h3>{% include icons/server.svg %} Self-hosted homelab resolver</h3>
        <p>Replace your router's DNS with something you control. Encrypted queries to upstream, full DNSSEC validation, local cache.</p>
        <pre><code>[server]
mode = "resolver"

[resolver]
forwarders = ["1.1.1.1", "9.9.9.9"]
dnssec = true
qname_minimization = true

[cache]
max_entries = 1_000_000
serve_stale = true</code></pre>
      </div>

      <div class="use-case">
        <h3>{% include icons/filter.svg %} Network-wide ad &amp; tracker blocking</h3>
        <p>Pi-hole-style blocking using standards-compliant Response Policy Zones. Drop in any BIND-compatible blocklist (Steven Black, hagezi, etc.) as an RPZ file.</p>
        <pre><code>[[rpz.zones]]
name = "rpz.adblock"
file = "/etc/rdns/rpz/blocklist.rpz"

[[rpz.zones]]
name = "rpz.malware"
file = "/etc/rdns/rpz/malware.rpz"</code></pre>
      </div>

      <div class="use-case">
        <h3>{% include icons/database.svg %} ISP / enterprise authoritative</h3>
        <p>Serve thousands of zones from PostgreSQL. <code>LISTEN/NOTIFY</code> drives hot reloads when zones change — no restart, no reload signal.</p>
        <pre><code>[server]
mode = "authoritative"

[authoritative]
source = "database"

[authoritative.database]
connection = "postgresql://rdns:..."</code></pre>
      </div>

      <div class="use-case">
        <h3>{% include icons/shield.svg %} High availability (CARP VIP)</h3>
        <p>Active-passive cluster behind a CARP virtual IP. rDNS listens on the wildcard, so failover is transparent to clients.</p>
        <pre><code>[listeners]
udp = ["0.0.0.0:53", "[::]:53"]
tcp = ["0.0.0.0:53", "[::]:53"]</code></pre>
        <p>Or bind both physical and VIP explicitly:</p>
        <pre><code>[listeners]
udp = ["192.168.1.1:53", "192.168.1.254:53"]
tcp = ["192.168.1.1:53", "192.168.1.254:53"]</code></pre>
      </div>

    </div>
  </div>
</section>

{% include cta.html %}
