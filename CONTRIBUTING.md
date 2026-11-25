# Contributing to rDNS

Thanks for your interest in rDNS. Bug reports, fixes, performance work and
documentation improvements are all welcome. This guide covers how to get set
up, what CI expects, and the conventions the codebase follows.

## Getting help and talking to us

Questions about using rDNS, ideas you want to discuss before writing code, or
help with a PR: join the [Zeros and Ones Discord](https://discord.gg/rkgcbQW93).
For bigger changes, it's worth checking there or opening an issue first so we
can agree on the approach.

## Reporting issues

- **Bugs and feature requests:** open a [GitHub issue](https://github.com/ZerosAndOnesLLC/rDNS/issues).
  For bugs, include the rDNS version (`rdns --version`), OS, the relevant part
  of your `rdns.toml` (redact anything private), and the query or steps that
  reproduce the problem.
- **Security vulnerabilities:** do **not** open a public issue. Report them
  privately as described in [SECURITY.md](SECURITY.md).

## Development setup

**Requirements**

- Rust **1.95 or newer** (the MSRV, declared as `rust-version` in `Cargo.toml`)
- Linux, macOS or FreeBSD
- Optional, for the PostgreSQL backend: PostgreSQL and
  [`sqlx-cli`](https://crates.io/crates/sqlx-cli) 0.9
  (`cargo install sqlx-cli --version 0.9.1 --no-default-features --features postgres,rustls`)

**Build and run**

```bash
cargo build                          # default features
cargo build --features postgres      # with the PostgreSQL zone backend
cargo run --bin rdns -- -c rdns.toml.example --check-config
cargo run --bin rdns -- -c rdns.toml.example
```

Binding port 53 needs root (or `CAP_NET_BIND_SERVICE`). For local testing,
point the listeners in a copy of `rdns.toml.example` at a high port instead.

## Project layout

| Path | What lives there |
|------|------------------|
| `src/main.rs`, `src/server.rs` | Startup, config loading, wiring the engines together |
| `src/listener/` | UDP (including batched I/O), TCP and DNS-over-TLS listeners |
| `src/protocol/` | DNS wire format: parsing and serialising messages, RDATA, EDNS |
| `src/resolver/` | Recursive resolution and forwarding |
| `src/auth/` | Authoritative engine, zone files, optional PostgreSQL backend |
| `src/cache/` | Sharded cache with TTL and negative caching |
| `src/dnssec/` | DNSSEC validation |
| `src/rpz/` | Response Policy Zones |
| `src/security/` | ACLs, rate limiting, privilege dropping, sandboxing (Capsicum on FreeBSD), PID files |
| `src/control/`, `src/bin/rdns_control.rs` | Unix-socket control interface and the `rdns-control` CLI |
| `migrations/` | sqlx migrations for the PostgreSQL backend |
| `bench/` | Benchmark harness (`run.sh`, `throughput.sh`) |
| `dist/`, `freebsd/` | systemd unit, rc.d script, manual FreeBSD build scripts |
| `docs/` | The project website (GitHub Pages) |

## Before you open a pull request

CI runs these on every PR, and all of them must pass before a merge. Run them
locally first:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --features postgres -- -D warnings
cargo test --locked
cargo deny --all-features check        # cargo install cargo-deny
```

CI additionally:

- runs the tests on Linux (x86_64, aarch64), macOS and FreeBSD 15,
- builds with the MSRV toolchain (`cargo +1.95 check --all-targets --features postgres`),
- applies the sqlx migrations to a real PostgreSQL,
- builds the Docker image, and
- runs `cargo publish --dry-run`.

If you touch platform-specific code (`#[cfg(target_os = ...)]`), keep in mind
it only compiles on that platform. The FreeBSD and macOS CI jobs are what check
it, so expect to iterate there if you can't build locally.

## Code conventions

- **Fix warnings, don't silence them.** Code must be clean under
  `clippy -D warnings`. Remove unused code rather than adding `#[allow]`.
- **No new `unsafe`** without discussing it with a maintainer first. The few
  existing `unsafe` blocks are syscalls with no safe wrapper (Capsicum,
  `fcntl` locks, `initgroups` on macOS). Any `unsafe` block needs a
  `// SAFETY:` comment explaining why it is sound. Prefer `nix` or `std`.
- **`mod.rs` files only declare and re-export modules.** Put structs,
  functions and impls in named sibling files.
- **Dates and times:** use `std::time`, `time` or `jiff`, never `chrono`.
- **SQL:** list columns explicitly; no `SELECT *`.
- **Hot path awareness:** the query path (listener → cache → response) is
  performance-critical. Avoid per-query allocations, locks and hashing where
  possible, and back performance claims with numbers (see *Performance changes*
  below).
- **Platform code:** gate it with `#[cfg(target_os = "...")]` and keep a
  sensible fallback for the other platforms.
- **New dependencies:** keep them to a minimum. They must pass `cargo deny`,
  which allows permissive licenses only (see `deny.toml`).

## Tests

- Tests live next to the code in `#[cfg(test)] mod tests` blocks.
- Every bug fix should come with a test that fails without the fix.
- Tests must not need network access, root, or a running DNS server.
- Tests run in parallel in one process. Never call anything that changes
  process-wide state in place, such as entering the sandbox or dropping
  privileges. Run it in a child process instead (see
  `src/security/sandbox.rs` for the pattern).

## Database migrations

Create migrations with sqlx so they get a correct timestamped name:

```bash
sqlx migrate add <description>
```

Then test them against a local PostgreSQL before opening the PR:

```bash
export DATABASE_URL=postgres://user:pass@localhost/rdns
sqlx migrate run
```

Never edit a migration that has already shipped in a release. Add a new one.

## Performance changes

For changes aimed at throughput or latency, include before/after numbers in
the PR. Use `bench/throughput.sh` (peak QPS) or `bench/run.sh` (latency under
load), and state the hardware, the concurrency level and the median of
several runs, as in [BENCHMARKS.md](BENCHMARKS.md).

## Commits and pull requests

- Branch from `main` and open the PR against `main`.
- Write commit subjects in the existing style, a type prefix and a short
  summary:
  `feat: …`, `fix: …`, `perf: …`, `test: …`, `docs: …`, `ci: …`, `chore: …`.
- Keep PRs focused. Separate unrelated changes into separate PRs.
- Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md)
  (create the section if it isn't there) for anything user-visible.
- Update [README.md](README.md) and the docs site (`docs/`) if you change
  behaviour, configuration or installation.
- **Don't bump the version** in `Cargo.toml`. Versions change only when a
  release is cut.

## Releases (maintainers)

1. Bump `version` in `Cargo.toml` (semver: major = breaking, minor =
   features, patch = fixes), turn `## [Unreleased]` in `CHANGELOG.md` into
   `## [X.Y.Z] - YYYY-MM-DD`, and commit as `chore: release X.Y.Z`.
2. Tag and push: `git tag -a vX.Y.Z -m "rDNS X.Y.Z" && git push origin vX.Y.Z`.
   `release.yml` builds the Linux, macOS and FreeBSD tarballs and creates the
   GitHub release as a **pre-release**.
3. After testing, promote it with
   `gh release edit vX.Y.Z --prerelease=false --latest`. This sends the
   release notifications and runs `publish.yml`, which pushes the Docker image
   to GHCR.
4. Publish to crates.io manually: `gh workflow run crates-io.yml -f tag=vX.Y.Z`
   (add `-f dry_run=true` to check first).

## License

rDNS is MIT licensed. By contributing, you agree that your contributions are
licensed under the same [MIT License](LICENSE).
