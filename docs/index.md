---
layout: default
title: null
description: rDNS is a high-performance Rust DNS server. Recursive resolver, authoritative, DNS-over-TLS, DNSSEC, RPZ. ~640K cached QPS, on par with multi-threaded Unbound. MIT licensed.
jsonld: software-application
---

<section class="hero">
  <div class="container">
    <p class="hero-eyebrow"><span class="dot"></span> v{{ site.version }} · MIT licensed · Production ready</p>
    <h1>A <span class="gradient-text">fast, safe</span> DNS server. Written in Rust.</h1>
    <p class="lead">Recursive resolver, authoritative server, DNS-over-TLS, DNSSEC validation, and RPZ filtering — in a single static binary. {% include icons/bolt.svg %}</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="{{ '/install/' | relative_url }}">Install rDNS →</a>
      <a class="btn btn-ghost" href="{{ '/benchmarks/' | relative_url }}">See the benchmarks</a>
    </div>

    <div class="stats-row">
      <div class="stat">
        <div class="stat-value">639,581</div>
        <div class="stat-label">queries per second (cached, 50 clients)</div>
      </div>
      <div class="stat">
        <div class="stat-value">98 µs</div>
        <div class="stat-label">cached query latency under load</div>
      </div>
      <div class="stat">
        <div class="stat-value">21×</div>
        <div class="stat-label">faster than the v1 baseline</div>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="container">
    <div class="section-title">
      <h4 class="label-uppercase">What's inside</h4>
      <h2>Everything a modern DNS server needs.</h2>
    </div>
    <div class="feature-grid">
      <div class="feature-card">
        {% include icons/globe.svg %}
        <h3>Recursive resolver</h3>
        <p>Full iterative resolution from root hints, with CNAME chain following and qname minimization.</p>
      </div>
      <div class="feature-card">
        {% include icons/server.svg %}
        <h3>Authoritative server</h3>
        <p>Serve zones from RFC 1035 zone files, or PostgreSQL with LISTEN/NOTIFY hot reload.</p>
      </div>
      <div class="feature-card">
        {% include icons/lock.svg %}
        <h3>DNS-over-TLS</h3>
        <p>RFC 7858 encrypted DNS on port 853, via rustls. No OpenSSL dependency.</p>
      </div>
      <div class="feature-card">
        {% include icons/shield.svg %}
        <h3>DNSSEC validation</h3>
        <p>Chain of trust verification from root trust anchors. Validated by default.</p>
      </div>
      <div class="feature-card">
        {% include icons/filter.svg %}
        <h3>RPZ filtering</h3>
        <p>Block or redirect domains via Response Policy Zones. Ad blocking, malware filtering, parental controls.</p>
      </div>
      <div class="feature-card">
        {% include icons/chart.svg %}
        <h3>Prometheus metrics</h3>
        <p>Per-listener QPS, cache hit rate, latency histograms — all exposed at <code>/metrics</code>.</p>
      </div>
    </div>
    <p class="mt-lg"><a href="{{ '/features/' | relative_url }}">See all features →</a></p>
  </div>
</section>

<section class="section">
  <div class="container split-row">
    <div>
      <h4 class="label-uppercase">Performance</h4>
      <h2>On par with multi-threaded Unbound. <span class="gradient-text">In Rust.</span></h2>
      <p>rDNS handles ~640K cached queries per second on commodity hardware — matching a fully multi-threaded Unbound, and ahead at low concurrency. The optimization journey from a naïve 29K-QPS baseline is documented step by step.</p>
      <p><a href="{{ '/benchmarks/' | relative_url }}">Read the benchmarks →</a></p>
    </div>
    <div>
      <div class="bench-chart">
        <div class="bench-row rdns">
          <span class="label">rDNS</span>
          <div class="track"><div class="bar" data-pct="100"></div></div>
          <span class="value">639,581</span>
        </div>
        <div class="bench-row unbound">
          <span class="label">Unbound</span>
          <div class="track"><div class="bar" data-pct="93"></div></div>
          <span class="value">596,564</span>
        </div>
      </div>
      <p class="label-uppercase">QPS, 50 cached clients, both on all cores</p>
    </div>
  </div>
</section>

<section class="section">
  <div class="container split-row">
    <div>
      <h4 class="label-uppercase">Safety</h4>
      <h2>Memory-safe by construction.</h2>
      <p>Written in Rust. No buffer overflows, no use-after-free, no double-frees — entire classes of CVEs eliminated at compile time. Privilege dropping after bind. FreeBSD Capsicum capability sandbox.</p>
      <p>rustls for TLS — no OpenSSL exposure.</p>
    </div>
    <div>
      <pre><code>[security]
sandbox = true
rate_limit = 1000

[server]
user = "rdns"
group = "rdns"</code></pre>
    </div>
  </div>
</section>

{% include cta.html %}
