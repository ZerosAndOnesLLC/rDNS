# rDNS GitHub Pages Marketing Site — Design

**Date:** 2026-05-11
**Status:** Approved, ready for implementation plan
**Goal:** Promote rDNS to maximize organic discovery (Google, GitHub, Reddit, HN) so SREs, ISP/enterprise operators, and the Rust/OSS community can find and adopt the project.

## Goals

- Maximize SEO surface — every page targets a distinct cluster of search intents.
- Land the pitch in <5 seconds on the home hero: "fast, safe, Rust DNS server, 437K QPS."
- Provide enough depth (features, benchmarks, use cases, comparisons) that a serious evaluator can decide without leaving the site.
- Zero ongoing maintenance overhead: Jekyll native build via GH Pages, no CI workflow, content lives in markdown alongside the code.

## Non-goals

- Blog / news section (just link to GitHub Releases in the footer).
- Analytics or tracking pixels (privacy-first; not required for SEO).
- Newsletter capture, Discord widget, or other engagement gadgets.
- Custom domain (decided to stay on `zerosandonesllc.github.io/rDNS/`).
- CI testing of the site (Jekyll builds in GH Pages; a broken build is loud).

## Audience

Broad. The site does not target one persona — rDNS's positioning is "high performance + Rust safety," which appeals to homelab self-hosters, ISP/enterprise operators, and OSS/Rust enthusiasts alike. Content is written so each audience can self-select via the page they land on.

## Architecture

### Location

Jekyll site lives in `/docs/` on the `main` branch. GitHub Pages source is configured as `main` branch + `/docs` folder. This co-locates marketing with code, version-controls it together, and avoids a separate `gh-pages` branch.

### Path conflict note

The spec/brainstorm artifacts in `/docs/superpowers/` must be excluded from Jekyll's build so they do not get rendered. This will be handled via `exclude:` in `_config.yml`:

```yaml
exclude:
  - superpowers/
  - vendor/
  - Gemfile
  - Gemfile.lock
```

### Build

Native GitHub Pages Jekyll — push to `main`, Pages builds automatically, no Actions workflow needed.

### File tree

```
docs/
  _config.yml              # site metadata, plugins, baseurl: /rDNS
  Gemfile                  # github-pages gem
  _layouts/
    default.html           # shell: <head>, nav, footer, JSON-LD slot
    page.html              # extends default, adds page header
  _includes/
    head-meta.html         # title, desc, canonical, OG, Twitter
    nav.html               # sticky top nav
    footer.html
    cta.html               # reused install + GH CTA block
  _sass/
    _base.scss
    _typography.scss
    _components.scss
    _hero.scss
  assets/
    css/main.scss
    js/main.js             # copy-code button, theme toggle, nav-toggle, bar-animate
    img/
      logo.svg
      og-image.png         # 1200x630 shared OG card
      og-{page}.png        # per-page OG variants
  index.md                 # Home
  features.md
  benchmarks.md
  install.md
  use-cases.md
  compare.md
  docs.md
  404.html
  sitemap.xml              # via jekyll-sitemap plugin
  robots.txt
  superpowers/             # excluded from Jekyll build (this spec lives here)
```

### Plugins

- `jekyll-sitemap` — sitemap.xml generation
- `jekyll-seo-tag` — fallback meta tags
- `jekyll-feed` — RSS for future use (release notes)
- `jekyll-redirect-from` — handle URL changes without losing link equity

## Pages

Each page has one primary keyword cluster, an H1 containing the primary keyword, a unique 150-160 char meta description, and unique body copy (not duplicated from README — Google penalizes duplication). Facts and code snippets are pulled from `BENCHMARKS.md`, `README.md`, and `rdns.toml.example`, with framing rewritten.

| Page | URL | Primary keywords | H1 |
|------|-----|------------------|----|
| Home | `/` | "rust dns server", "rdns" | A fast, safe DNS server. Written in Rust. |
| Features | `/features/` | "dns-over-tls server", "rust dnssec resolver", "rpz filtering" | Everything a modern DNS server needs. |
| Benchmarks | `/benchmarks/` | "fastest dns server", "unbound alternative", "dns benchmark" | 437,434 queries per second. 32 microsecond latency. |
| Install | `/install/` | "install dns server linux", "freebsd dns server", "dns docker" | Install rDNS in 60 seconds. |
| Use Cases | `/use-cases/` | "self hosted dns", "homelab dns", "isp dns server" | Built for every scale, from homelab to ISP. |
| Compare | `/compare/` | "unbound vs", "bind alternative", "powerdns alternative", "coredns vs", "pihole alternative" | rDNS vs Unbound, BIND, PowerDNS, CoreDNS, Pi-hole. |
| Docs | `/docs/` | "rdns configuration", "rdns toml" | Configuration reference. |

### Page sections

**Home** — Hero (gradient headline + 2 CTAs + 437K QPS stat badge), 6-feature grid, "Why rDNS" 3-up (Fast / Safe / Flexible), benchmark teaser chart, install snippet, GitHub CTA footer.

**Features** — One section per capability: Recursive resolver, Authoritative (zone files + PostgreSQL), DNS-over-TLS, DNSSEC validation, RPZ filtering, Sharded cache w/ serve-stale, Control CLI, Prometheus metrics, Security hardening (Capsicum, privilege dropping), Cross-platform.

**Benchmarks** — Test environment, head-to-head table, animated CSS bar charts (QPS by client count), latency comparison, the v1→v5 optimization journey, methodology, reproduce-it section with `dnsperf` invocation.

**Install** — Tabbed install paths: Linux systemd, FreeBSD rc.d, Docker, Cargo build, source build. Each with copy-able code blocks and post-install verify steps (`dig @127.0.0.1 example.com`).

**Use Cases** — Four cards w/ config snippets: Homelab resolver, Network-wide ad/tracker blocking (RPZ), ISP/enterprise with PostgreSQL backend, AiFw HA deployment with CARP VIP.

**Compare** — Comparison matrix table across Unbound / BIND / PowerDNS / CoreDNS / Pi-hole on dimensions (language, perf, DoT, DNSSEC, authoritative, RPZ, license, sandbox). Then short prose section per competitor with honest tradeoffs (where rDNS is younger or missing features).

**Docs** — Full TOML configuration reference (all sections from `rdns.toml.example`), `rdns-control` CLI commands, metrics endpoint shape, log format. Authoritative source links to GitHub.

## SEO mechanics

Applied to every page:

- `<title>`: `<Page topic> — rDNS` (keyword first, brand last, ≤60 chars)
- `<meta name="description">`: unique 150-160 chars with primary keyword in first 120 chars
- `<link rel="canonical">`: absolute URL, prevents duplicate-content split
- Open Graph + Twitter cards: title, description, og:image (1200×630), og:type=website
- JSON-LD `SoftwareApplication` schema on Home: name, applicationCategory: DeveloperApplication, operatingSystem (Linux/FreeBSD/macOS), license MIT, downloadUrl → GitHub releases, softwareVersion
- JSON-LD `FAQPage` schema on Compare page (high-intent search snippets)
- JSON-LD `BreadcrumbList` on inner pages
- Semantic HTML5: one `<h1>` per page, ordered `<h2>` sections, `<nav>`, `<main>`, `<article>`, `<footer>`
- Internal linking: every page links Home → Features → Benchmarks → Install (funnel); Compare cross-links to Features for each claim
- `sitemap.xml` + `robots.txt`: auto via `jekyll-sitemap`; robots allows all and points to sitemap
- `404.html`: helpful, links back to nav (GH Pages serves on missing routes)
- Image alt text: descriptive on every `<img>`; decorative SVGs get `aria-hidden`

## Performance

Lighthouse target: ≥95 across all four categories on all 7 pages.

- Page weight budget: <100KB transferred on first load
- No web fonts (system font stack only — zero render-blocking font requests)
- Inline critical CSS in `<head>`
- Lazy-load below-fold images (`loading="lazy"`)
- No JS frameworks — vanilla, <5KB total
- All assets paths use `{{ site.baseurl }}` so the `/rDNS/` subpath works

## Visual system

Direction B from brainstorming — "Modern / Polished" (gradient hero, Vercel/Linear feel).

### Color tokens

```
--bg-base:       #0a0e1a   (deep navy-black)
--bg-elevated:   #111827   (cards, code blocks)
--bg-subtle:     #1e293b   (hover, dividers)
--border:        #1f2937
--text-primary:  #f8fafc
--text-secondary:#94a3b8
--text-muted:    #64748b
--accent-from:   #a5b4fc   (gradient start — indigo-300)
--accent-to:     #f0abfc   (gradient end — fuchsia-300)
--accent-solid:  #818cf8   (links, focus rings)
--success:       #34d399   (perf wins in tables)
--rust:          #ce4218   ("written in Rust" accents)
```

Dark mode default; light mode toggle persists in `localStorage` and respects `prefers-color-scheme` on first visit.

### Typography

System font stack — zero font requests, instant render:

```
--font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Inter, sans-serif;
--font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
```

- H1: 56px desktop / 36px mobile, weight 800, tracking -0.02em
- H2: 36px / 28px, weight 700
- Body: 17px, line-height 1.65, weight 400
- Code: 14px mono

### Components

- **Stat badge** — large gradient number + small label ("437K QPS", "32µs latency", "14.8× faster")
- **Feature card** — inline SVG icon, H3, 2-line description, hover lifts +2px with border-glow
- **Benchmark bar** — pure CSS `width: %`, animated on scroll-into-view via `IntersectionObserver`
- **Code block** — `<pre>` with copy button (top-right), language label, elevated background
- **Comparison table** — sticky header, alternating row tint, checkmark/dash cells
- **Section divider** — thin gradient line, no decorative headers

### Responsive

Mobile-first. Breakpoints: 640 / 768 / 1024 / 1280. Nav collapses to hamburger ≤768.

### Accessibility

- WCAG AA contrast minimum across both themes
- Visible focus rings on all interactives
- Keyboard-navigable nav (including mobile drawer)
- `prefers-reduced-motion` disables scroll animations
- Theme toggle has accessible label

### JavaScript

Vanilla, no framework, <5KB total:

- Theme toggle (dark ↔ light, persists)
- Copy-to-clipboard for code blocks
- Mobile nav toggle
- `IntersectionObserver` for benchmark bar animation

## Launch checklist

1. Create `/docs/` with full Jekyll structure per file tree above
2. Build the 7 pages with unique content + SEO metadata
3. Generate `og-image.png` (shared) and per-page variants
4. Add `_config.yml` with site title, description, baseurl `/rDNS`, plugins, `exclude: [superpowers/]`
5. Enable GH Pages: Settings → Pages → source `main` branch, `/docs` folder
6. Verify build succeeds and site loads at `https://zerosandonesllc.github.io/rDNS/`
7. Run Lighthouse on all 7 pages — must hit ≥95 across all categories
8. Validate HTML at validator.w3.org
9. Submit `sitemap.xml` to Google Search Console + Bing Webmaster Tools
10. Add site link to repo "About" sidebar on GitHub
11. Cross-link `README.md` and `BENCHMARKS.md` → live benchmarks page
12. Increment `Cargo.toml` version per project convention, commit
13. Announce: r/rust, r/selfhosted, r/homelab, Hacker News (Show HN), Lobsters

## Off-site SEO / promotion

- Submit sitemap to Google Search Console + Bing Webmaster
- Link the site from GitHub repo "About" sidebar
- Cross-link `README.md` and `BENCHMARKS.md` to the live benchmarks page
- Reddit launch posts: r/rust, r/selfhosted, r/homelab
- Hacker News "Show HN"
- Lobsters
- Optional later: DEV.to or Medium repost of the optimization journey with canonical URL pointing at `/benchmarks/`

## Content sourcing rules

- Pull facts and code snippets from `BENCHMARKS.md`, `README.md`, and `rdns.toml.example`
- Rewrite framing/prose for each page — Google penalizes verbatim duplication
- Treat GitHub as the source of truth; the site links back, never replaces

## Open questions for implementation plan

- Exact set of feature icons (inline SVG) — pick from Lucide/Heroicons or hand-roll
- OG image generation tooling — manual in Figma, or programmatic via a one-shot script
- Whether to include a "release version" stat block on home that auto-updates from `Cargo.toml` (Jekyll can read it via `_data/`)
