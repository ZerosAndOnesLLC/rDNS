---
layout: page
title: Install
heading: Install rDNS in 60 seconds.
eyebrow: Install
lede: Single static binary. systemd unit, FreeBSD rc.d script, and Dockerfile included.
description: Install rDNS on Linux (systemd), FreeBSD (rc.d), or Docker. Build from source via Cargo. Full quick-start with config and verification steps.
---

<section class="section">
  <div class="container">

    <div class="tabs">
      <div class="tablist" role="tablist" aria-label="Install method">
        <button role="tab" aria-controls="tab-linux" aria-selected="true">Linux (systemd)</button>
        <button role="tab" aria-controls="tab-freebsd" aria-selected="false">FreeBSD (rc.d)</button>
        <button role="tab" aria-controls="tab-docker" aria-selected="false">Docker</button>
        <button role="tab" aria-controls="tab-cargo" aria-selected="false">Cargo</button>
        <button role="tab" aria-controls="tab-source" aria-selected="false">From source</button>
      </div>

      <div role="tabpanel" id="tab-linux">
        <h3>Linux with systemd</h3>
        <p>Build, install, enable.</p>
        <pre><code># Build (Rust 1.85+)
cargo build --release

# Install
sudo install -Dm755 target/release/rdns /usr/local/bin/rdns
sudo install -Dm755 target/release/rdns-control /usr/local/bin/rdns-control
sudo install -Dm644 rdns.toml.example /etc/rdns/rdns.toml
sudo install -Dm644 dist/rdns.service /etc/systemd/system/rdns.service

# Create user
sudo useradd -r -s /usr/sbin/nologin rdns

# Run
sudo systemctl daemon-reload
sudo systemctl enable rdns
sudo systemctl start rdns</code></pre>

        <h4>Verify</h4>
        <pre><code>dig @127.0.0.1 example.com
sudo systemctl status rdns
rdns-control stats</code></pre>
      </div>

      <div role="tabpanel" id="tab-freebsd" hidden>
        <h3>FreeBSD with rc.d</h3>
        <pre><code># Build
cargo build --release

# Install
sudo install -m 755 target/release/rdns /usr/local/bin/rdns
sudo install -m 755 target/release/rdns-control /usr/local/bin/rdns-control
sudo install -m 644 rdns.toml.example /usr/local/etc/rdns/rdns.toml
sudo install -m 755 dist/rdns.rc /usr/local/etc/rc.d/rdns

# Enable and start
sudo sysrc rdns_enable=YES
sudo service rdns start</code></pre>

        <p>FreeBSD builds use Capsicum sandboxing automatically.</p>
      </div>

      <div role="tabpanel" id="tab-docker" hidden>
        <h3>Docker</h3>
        <pre><code># Build the image
docker build -t rdns .

# Run
docker run -d \
  -p 53:53/udp \
  -p 53:53/tcp \
  -v /etc/rdns:/etc/rdns \
  --name rdns \
  rdns</code></pre>

        <h4>Verify</h4>
        <pre><code>dig @127.0.0.1 example.com
docker logs rdns</code></pre>
      </div>

      <div role="tabpanel" id="tab-cargo" hidden>
        <h3>Cargo install</h3>
        <pre><code># From the repository
cargo install --path .

# With PostgreSQL backend
cargo install --path . --features postgres</code></pre>

        <p>This places <code>rdns</code> and <code>rdns-control</code> in <code>~/.cargo/bin/</code>.</p>
      </div>

      <div role="tabpanel" id="tab-source" hidden>
        <h3>From source</h3>
        <pre><code>git clone https://github.com/ZerosAndOnesLLC/rDNS.git
cd rDNS

# Release build with native CPU optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Validate config
./target/release/rdns -c rdns.toml.example --check-config

# Run
./target/release/rdns -c rdns.toml.example</code></pre>
      </div>
    </div>

    <h2 class="mt-lg">Configuration</h2>
    <p>rDNS uses TOML. Copy <code>rdns.toml.example</code> and adjust. The most common starting point is forwarder mode:</p>
    <pre><code>[server]
mode = "resolver"

[listeners]
udp = ["0.0.0.0:53", "[::]:53"]
tcp = ["0.0.0.0:53", "[::]:53"]

[resolver]
forwarders = ["1.1.1.1", "8.8.8.8"]
dnssec = true</code></pre>

    <p>See the <a href="{{ '/docs/' | relative_url }}">configuration reference</a> for every option, or the <a href="{{ '/use-cases/' | relative_url }}">use cases</a> page for ready-made configs.</p>
  </div>
</section>

{% include cta.html %}
