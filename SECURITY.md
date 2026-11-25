# Security Policy

## Supported Versions

Only the latest released version of rDNS receives security fixes. Please
upgrade to receive patches.

| Version | Supported |
|---------|-----------|
| 1.19.x  | ✅        |
| < 1.19  | ❌        |

## Reporting a Vulnerability

Please report security vulnerabilities privately. Do **not** open a public
GitHub issue or post details in the Discord.

- **GitHub:** use [private vulnerability reporting](https://github.com/ZerosAndOnesLLC/rDNS/security/advisories/new)
- **Email:** support@zerosandones.us (subject line starting with `[SECURITY]`)

Include, where possible:

- A description of the vulnerability and its impact
- Steps to reproduce (a minimal `rdns.toml` and the query or packet that
  triggers it are ideal)
- The rDNS version (`rdns --version`) and platform affected
- Whether you would like to be credited

## What to Expect

- **Acknowledgement** within 72 hours
- **Assessment and severity triage** within 7 days
- **Fix and coordinated disclosure:** we aim to release a patched version
  before public disclosure, publish a GitHub Security Advisory alongside it,
  and credit reporters in the release notes unless they prefer otherwise

We ask that you give us reasonable time to release a fix before disclosing
publicly.

## Scope

In scope: anything exploitable in the `rdns` and `rdns-control` binaries, the
`rdns-server` crate, the release tarballs and the GHCR container image. For
example:

- Memory-safety or panic bugs reachable from network input (malformed DNS
  messages, EDNS options, zone or RPZ data)
- Cache poisoning or response spoofing
- DNSSEC validation bypasses
- ACL or rate-limit bypasses
- Denial-of-service vectors, including amplification
- Privilege-dropping or sandbox escapes
- Unsafe defaults

Out of scope:

- Vulnerabilities in upstream resolvers or authoritative servers rDNS talks to
- Misconfigured deployments (for example an internet-facing resolver with no
  `allow_recursion`), unless a default makes the mistake easy
- Issues that require local root or access to the host
- Already-public vulnerabilities in dependencies. Report those upstream. We
  track them with `cargo deny` in CI and update promptly.

## Security Considerations

rDNS is network infrastructure that usually starts as root to bind port 53.
Key security properties and the settings that matter:

### Network exposure

- **Open resolver risk:** `security.allow_recursion` is empty by default,
  which allows recursion from **any** source. On any server reachable from the
  internet, set it to your client networks, for example
  `allow_recursion = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]`. Otherwise
  the server can be abused for DNS amplification attacks.
- **Rate limiting:** `security.rate_limit` (default 1000 queries/second per
  source IP) is a per-IP token bucket. Memory is bounded by capping tracked
  IPs per shard. Set it to `0` only behind another rate limiter.
- **TCP and DNS-over-TLS** connections are capped (512 TCP, 256 DoT) to bound
  resource use.
- **Metrics** (`[metrics]`) are disabled by default and bind to
  `127.0.0.1:9153` when enabled. Keep them on localhost or a management
  network.

### Spoofing and cache poisoning

- Query IDs come from the OS CSPRNG (`getrandom`).
- Recursive queries to authoritative servers use a fresh UDP socket with an
  OS-assigned ephemeral source port per query.
- DNSSEC validation (`resolver.dnssec`, on by default) verifies the chain of
  trust from the root trust anchors.

### Privilege reduction and sandboxing

- After binding its ports, rDNS drops to `server.user` / `server.group`
  (default `rdns`), resets supplementary groups, and verifies that root can't
  be regained.
- `security.sandbox` (on by default) enters Capsicum capability mode on
  FreeBSD, and sets `NO_NEW_PRIVS` and non-dumpable on Linux.
- The systemd unit (`dist/rdns.service`) adds `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome` and `PrivateTmp`. The container image
  runs as the unprivileged `rdns` user.

### Control interface

- The control socket (`control.socket`) is created with `0660` permissions.
  Anyone who can connect to it can flush the cache and reload RPZ zones, so
  keep its directory owned by the `rdns` user and group.

### Secrets and data

- The PostgreSQL connection string, including its password, and the DoT
  private key are read from disk. Restrict `rdns.toml` and the key file to
  the `rdns` user (`chmod 600`).
- Zone files, RPZ files and database contents are trusted input. Anyone who
  can modify them controls the answers rDNS serves.

### Supply chain

- CI runs `cargo deny` on every change (RustSec advisories, licenses,
  dependency sources), and Dependabot keeps dependencies and GitHub Actions
  current.
- Release tarballs ship with a `SHA256SUMS` file and GitHub build-provenance
  attestations:
  `gh attestation verify <file> --repo ZerosAndOnesLLC/rDNS`.
