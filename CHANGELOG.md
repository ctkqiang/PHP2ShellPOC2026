# Changelog

## Unreleased — decision report, block-page handling and authorized POC

- Each target now gets a `DECISION` card that answers the question the scan
  exists to answer — *can this host be hacked by PHP2Shell?* — as
  `EXPOSED — YES`, `LIKELY EXPOSED — YES`, `NOT EXPOSED — NO` or
  `INCONCLUSIVE — UNKNOWN`, with a plain-language statement and the single
  `ACTION` that follows from it. The bottom line now leads with the same
  answer (`YES — N targets hackable via PHP2Shell` / `UNKNOWN — …` /
  `NO — …`), and the assessment-table `Hackability` cell prefixes it too.
- `hackability` results carry `answer` (`yes`/`no`/`unknown`; `LIKELY`
  answers `yes` because the burden is on disproving exposure) and `action`
  (the one sentence of advice the answer implies). JSON exposes both under
  `results.<target>.hackability`; Markdown prints a `Decision:` line per
  target and a `Hackable?` column in the summary table; CSV adds `hackable`,
  `answer` and `decision_action`; SARIF result properties and messages carry
  the same decision. Chinese translations cover the card, the answer words
  and the actions.
- After a text-mode scan finds an exposed host, the tool asks one y/N question
  and, on `y`, prints the authorized-use warning before running the Ruby lab
  POC. There is no POC flag. The POC uses raw HTTP/1.1 and preserves the lab
  POC's multipart layout, heap/library leak math, offsets, retries, worker
  rotation and `out/p1` proof, and is isolated under
  `lib/php2shell_poc2026/poc/`. Its prompt, warning, progress lines and result
  card follow the text report language. Every run ends with an explicit
  `RESULT: SUCCESS` or `RESULT: FAILED`; `-v` adds the technical addresses and
  the recorded output log. See [docs/POC.md](docs/POC.md).
- Added a Simplified Chinese README (`README_zh.md`) covering the scanner,
  the authorized POC prompt, localization, safety properties and the POC
  limitations.
- The default text report is now plain language: a `HACKABLE?` findings
  column, a `DECISION` card, a `WHAT THIS MEANS` card and two next steps.
  Scores, ratios, SAPI names, ATT&CK, defender checks, the evidence table and
  the full remediation list moved behind `-v`.
- Block pages are fingerprinted instead of being reduced to an anonymous
  `403`: OVHcloud, Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5,
  Wordfence and ModSecurity are recognised from headers, titles and body
  text. The report names the vendor and the message, and when the block is
  likely User-Agent-sensitive it offers an explicit `--browser-ua` retry.
- `--browser-ua` sends a browser-compatible User-Agent for bot-protection
  compatibility. It is opt-in, labelled in the report, and never automatic:
  it can cross a bot-control boundary, so it requires authorization.
- A branch-only version on an end-of-life branch (for example `PHP/8.1`) is
  now `eol` / exposed instead of `unknown`. Branch-only versions on branches
  that still receive fixes remain `branch_only` / unverified.
- When PHP is present but its version is hidden, the plain report says
  `PHP present, version hidden` instead of an ambiguous `unknown`; the reason
  is "PHP was detected, but the version was not exposed." This is the common
  case on modern sites that strip `X-Powered-By`.
- Statamic, Craft CMS, Magento, PrestaShop and OpenCart are now detected as
  PHP evidence, so a site using one of them is not falsely reported as
  "no PHP seen" just because the framework hides the `X-Powered-By` version.
- Blocked or otherwise unverified hosts print `not observed` for PHP surface
  fields, not `no`: a 403 is not evidence that PHP is absent.
- The text report now follows the device language automatically: Simplified
  Chinese when the locale is `zh*`, English otherwise. `--lang en|zh`,
  `-en` and `-zh` override detection; `PHP2SHELL_LANG` provides the same
  override without a flag, before `LC_ALL`/`LC_MESSAGES`/`LANGUAGE`/`LANG`
  and the macOS user locale.
- The Chinese text report covers UI labels, verdict/access/risk wording,
  ATT&CK and detection prose, red-team notes, next actions, remediation and
  the run summary. Missing entries fall back to English instead of showing a
  translation key.
- CJK-aware layout: Chinese, fullwidth characters and emoji count as two
  terminal columns; wrapping and table padding use display width, and closing
  punctuation is kept off the start of a line.
- JSON, Markdown, SARIF, CSV and NDJSON remain English, and the CLI pins
  their locale to `en` so a Chinese workstation cannot change a machine
  contract.
- The text report now leads with the bottom line and a plain-language "Next"
  step, before the findings table.
- Verdicts are printed as words (`INCONCLUSIVE`, `VULNERABLE`, `PATCHED`,
  `UNVERIFIED`, `END-OF-LIFE`, `NO PHP`) and risk as a full grade
  (`CRITICAL`, `HIGH`) instead of truncated codes (`INCON`, `VULN`, `CRIT`).
- Automatic colour on a TTY for verdicts, risk, section headings and table
  state; `--no-color`, `NO_COLOR`, `--output` and piped stdout stay plain.
- Assessment cards omit empty rows (`Edge` when it duplicates `Server`, `CDN`
  when none was seen, `Framework` when none was observed).
- The toolchain is one line per tool; `--toolchain-full` adds the rationale
  and the lower-priority entries.
- Next actions are prioritised: the default view shows the four actions that
  can resolve the verdict, `-v` shows the full list with rationale. Exposed
  targets now include the SARIF handoff and sibling-host inventory actions
  (the `:exposed` branch could never match an actual verdict status).
- Duplicate ATT&CK `T1592` entries on unverified targets are merged into one.
- The tips footer only advertises flags that were not already used.
- Text width is capped at 110 columns for readability on wide terminals.

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
