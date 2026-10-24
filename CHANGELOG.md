# Changelog

## 3.0.0 — 2026-10-24

### The headline

A `403` is no longer reported as "not hackable". The scanner now distinguishes
blanket edge denial, path-level restriction, auth walls, soft-404 routing,
rate limiting, server errors and unreachable hosts. When it cannot see the
application, the verdict is `inconclusive` and the evidence ratio is `null`,
not `0.00`.

### Scan model

- Random canary probes (`/php2shell-<hex>.txt` and `.php`) to detect blanket
  denial and catch-all routing.
- Adaptive early exit for blocked, auth-wall, soft-404, rate-limited,
  server-error and unreachable targets.
- Root/control differential classification with a conservative similarity
  threshold.
- PHP-FPM/CGI "File not found" bodies treated as positive PHP evidence.
- Branch-only versions (`8.2`) reported as `unknown` / `branch_only` instead
  of a patch-level guess.
- Fix floors: 8.2.35, 8.3.36, 8.4.27, 8.5.12; 5.x/7.x/8.0/8.1 are EOL.
- Deep mode reads `robots.txt` and a same-host sitemap, then requests at most
  five published `.php` paths. No brute-forcing.
- Per-target request budget, per-host rate limiting, redirect cap, body cap,
  retries, proxy support and TLS certificate capture.
- Scope files with exact hosts, subdomains, wildcards, IPs, CIDRs and URLs;
  `--require-scope` fails closed with exit code `4`.

### Decision model

- New statuses: `vulnerable`, `eol`, `patched`, `unknown`, `no_php`,
  `inconclusive`.
- Access states: `open`, `blocked`, `restricted`, `auth_wall`,
  `rate_limited`, `soft_404`, `server_error`, `unreachable`, `unknown`.
- Exposure severity separated from exploit friction. WAF/CDN/FPM/auth do not
  lower the exposure score.
- `hackability.ratio` is `null` when there is no positive or negative
  evidence.
- `patched` and `no_php` remain scoped claims, not estate-wide certification.

### Reporting

- New text report is a dashboard: findings table, bottom line, assessment
  card, evidence table, compact ATT&CK/detections, numbered next actions and
  run summary. `-v` expands technical detail; `-c` adds the toolchain; `-r`
  adds red-team notes.
- Formats: text, JSON (schema `3.0`), Markdown, SARIF 2.1.0, CSV and NDJSON.
- `--output`, `--compact`, `--quiet`, `--no-banner`, `--evidence`.
- Every format uses the same computed `Summary`, so counts cannot drift.
- Terminal-aware layout: Unicode-safe wrapping, hanging indents, stacked rows
  on narrow terminals, `COLUMNS` support.
- Target-derived text sanitised for ANSI/OSC/control/bidi, Markdown and CSV.

### CLI and distribution

- Profiles: `passive`, `standard`, `deep` (`-d` remains an alias).
- YAML config files (`--config`) with relative path resolution and fail-closed
  unknown keys.
- Threaded multi-target scans with a shared per-host rate limiter.
- `--dry-run` prints the request plan and opens no socket.
- Exit codes: `0` clear/unverified, `1` error, `2` exposed, `3` inconclusive
  (`--fail-on`), `4` scope violation.
- Offensive tooling gated behind `--authorized`.
- Global install: gem, `php2shell` alias, `install.sh`, Dockerfile, CI and
  release workflows.
- Ruby `>= 2.7`; no runtime dependencies.

### Tests

- Minitest suite covering blocked 403, restricted, soft-404, auth wall, 429,
  unreachable, vulnerable/patched/EOL, branch-only, phpinfo, FPM 404, deep
  discovery, budget caps, HTTP transport, redirects, gzip, body caps, IDN,
  scope, options, sanitisation, layout, all report formats and CLI dry-run /
  scope / config / output behaviour.

### Breaking changes from 2.x

- `Report.json` and the old flat JSON shape are replaced by the v3 envelope.
- `unknown` no longer means "not hackable"; it means unverified.
- `risk.score` is `null` for unverified targets.
- `hackability.ratio` is `null` when there is no evidence.
- CLI exit codes are now `0/1/2/3/4` (2 was already exposure; 3 and 4 are new).
- `--deep` is an alias for `--profile deep`; `--json` is an alias for
  `--format json`.
