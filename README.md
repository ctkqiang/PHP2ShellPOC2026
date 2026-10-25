# PHP2ShellPOC2026

[English](README.md) | [简体中文](README_zh.md)

PHP2Shell exposure triage with an authorized lab POC for the **PHP2Shell** bug
class (CVE-2026-109618 and CVE-2026-109619). The headline answer is the decision
the operator needs —
**can this host be hacked by PHP2Shell: YES, NO or UNKNOWN** — followed by the
evidence, the caveats and the action that follows. Point it at a web endpoint
and it answers four questions in one report:

1. **What is actually answering?** PHP version, SAPI, edge, CDN, WAF, framework.
2. **Is the interpreter exposed?** Below the branch fix level, end-of-life,
   patched, or genuinely unverified.
3. **How much does the deployment change the picture?** Exposure severity is
   reported separately from exploit friction.
4. **What should happen next?** ATT&CK mapping, detection opportunities,
   remediation, and copy-pasteable next actions.

The scanner sends ordinary `GET` requests. When an interactive text-mode scan
finds an exposed host, it asks one question — whether to run the authorized
lab POC — and only an explicit `y` starts the POST/multipart exploit flow.
There are no POC flags.

> **Authorized use only.** This is a triage tool, not a permission slip.
> Confirm the program scope, rules of engagement and rate limits before you
> point it at anything. `--scope` and `--require-scope` exist to make that
> boundary enforceable, not decorative. The POC is calibrated for the
> bookworm PHP 8.4.26 lab build, can disrupt the target, and is never a
> substitute for written authorization. See
> [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md).

---

## Why 3.0 exists

The 2.x model had a dangerous failure mode: a host that returned `403` to
every request was reported as **not hackable**, with a `0.00` evidence ratio.
That is not what a `403` means. It means the scanner could not see the
application. Absence of evidence was being sold as evidence of absence.

3.0 changes the questions the tool asks:

- A random **canary path** is fetched alongside the root. If the canary is
  denied too, the result is `BLOCKED` / `INCONCLUSIVE`, not "clean".
- Catch-all routing is detected as **soft-404**; path status codes stop being
  trusted.
- A login redirect is an **auth wall**, not a patched interpreter.
- A `429` is **rate limiting**, not absence.
- Version evidence is separated from **access evidence**. A `403` page that
  leaks `X-Powered-By` still reports the version, with low confidence and an
  explicit caveat.
- **Exposure severity** (`9.8` for a vulnerable interpreter) is separate from
  **exploit friction** (WAF, CDN, FPM worker affinity, auth wall). A WAF does
  not make an unpatched parser less unpatched.
- When there is no positive or negative evidence, the evidence ratio is
  `null`, not `0.00`.
- Reports are available as text, JSON, Markdown, SARIF, CSV and NDJSON.
- Offensive tooling recommendations are gated behind `--authorized`.
- `--dry-run` prints the exact request plan without opening a socket.
- `--scope` / `--require-scope` fail closed with exit code `4`.

---

## Install

### RubyGems

```sh
gem install php2shell_poc2026
php2shell --version
```

### From a checkout

```sh
git clone https://github.com/ctkqiang/PHP2ShellPOC2026.git
cd PHP2ShellPOC2026
./install.sh            # system gem
./install.sh --user     # user gem directory
```

The gem has **no runtime dependencies**. Ruby `>= 2.7` and RubyGems are
enough. The POC is Ruby standard library only; there is no Python runtime or
external exploit script.

### Docker

```sh
docker build -t php2shell-poc2026 .
docker run --rm php2shell-poc2026 --version
docker run --rm php2shell-poc2026 --dry-run https://example.com/
```

The image runs as an unprivileged user and only needs outbound HTTP(S).

---

## Quick start

```sh
# Passive: root + one text canary, no .php probing
php2shell --profile passive https://example.com/

# Standard: root, text/php canaries, /index.php, framework paths if detected
php2shell https://example.com/

# Deep: common PHP paths, framework paths, robots.txt and sitemap.xml discovery
php2shell -d https://example.com/

# Deep + expert appendix: technical detail, attacker notes and tools
php2shell -d -r -c -v https://example.com/

# Machine-readable report
php2shell --json https://example.com/ > report.json

# Plan first; no socket is opened
php2shell --dry-run --profile deep https://example.com/

# Chinese text report; omit the language flag to follow the device locale
php2shell --lang zh https://example.com/
php2shell -zh https://example.com/     # same thing, shorter
php2shell -en https://example.com/     # force English
```

The default text report is deliberately short. The bottom line answers the
question the scan exists to answer — *can this host be hacked by PHP2Shell?* —
as `YES` / `UNKNOWN` / `NO` with the one next step that follows from it. Then
a findings table with a plain `HACKABLE?` column, and per host: a `DECISION`
card, a `WHAT THIS MEANS` card (result, why, confidence, evidence, PHP version
and fix), and the two most useful next steps. `-v` adds the technical details,
pages checked, attack-path notes, defender checks, all next steps, the full
fix list and the request trace. `-c` adds tools, `--toolchain-full` adds the
reasoning and lower-priority entries, `-r` adds attacker notes, and `--quiet`
keeps only the bottom line, findings table and run summary.

Colour is used only when stdout is a terminal; redirected output, `--output`,
`NO_COLOR` and `--no-color` stay plain.

The text report follows the device language: Simplified Chinese when the
system locale is `zh*` (for example `zh_CN.UTF-8` or macOS `zh-Hans-CN`),
English otherwise. `--lang en`, `--lang zh`, `-en` and `-zh` override
detection, and `PHP2SHELL_LANG` does the same without a flag. Resolution order
is the language flag, `PHP2SHELL_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`,
`LANG`, then the macOS user locale; unsupported languages fall back to
English. Width, wrapping and table alignment are computed with CJK characters
counted as two columns, and closing punctuation is kept off the start of a
line. The POC prompt, warning, progress and result follow the same language.
Machine formats (`json`, `markdown`, `sarif`, `csv`, `ndjson`) always keep
English messages so their contracts stay stable, and they never run the POC.

---

## How it works

### 1. Scope and target normalisation

Every target is parsed once into a `Target` object. Bare hostnames become
`https://…/`; IDNs are Punycoded for the wire; IPv6 literals are bracketed;
credentials in URLs are rejected (use `--basic-auth` or `--bearer`). Scope is
checked **before** the first socket is opened.

### 2. Root + control probes

The scanner fetches the root, then one or two random canary paths such as
`/php2shell-<8hex>.txt` and `/php2shell-<8hex>.php`. The canary is the key
methodological change:

| Root | Canary | Classification |
|---|---|---|
| `403` | `403` | **blocked** — the edge denied the scanner |
| `403` | `404` | **restricted** — path-level access control |
| `200` | `200`, same body | **soft-404** — catch-all routing |
| `302` to login | anything | **auth wall** |
| `429` | anything | **rate limited** |
| `5xx` | anything | **server error** |
| error | error | **unreachable** |
| `200` | `404` | **open** — path statuses are usable |

Adaptive mode stops after the controls for blocked, auth-wall, rate-limited,
soft-404, server-error and unreachable results. `--no-adaptive` forces the
full probe set when you have a reason to.

### 2b. Block-page fingerprinting

A denial page is still evidence about the edge. The scanner recognises common
block pages — OVHcloud, Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5,
Wordfence and ModSecurity — and reports the vendor plus the message the page
showed. If the block is likely User-Agent-sensitive, the report says so and
offers an explicit retry:

```sh
php2shell --browser-ua https://example.com/
```

`--browser-ua` is never automatic. It sends a browser-compatible
`User-Agent`, which can cross a bot-control boundary, so the report labels the
mode and the operator must confirm authorization. The default remains the
identifying `php2shell-poc2026` User-Agent.

### 3. Version evidence

Version is read from, in order:

- `X-Powered-By`, `Server` and any header carrying `PHP/<version>`.
- `phpinfo()` pages, including `<title>phpinfo()</title>` and `PHP Version`.
- Framework metadata (WordPress/Drupal/Joomla) is recorded as **framework**
  version context, never as the PHP patch level.

A branch-only value such as `8.2` is reported as `UNVERIFIED` / `branch_only`,
not silently upgraded to a patch-level claim. A branch-only value on an
end-of-life branch such as `8.1`, `8.0` or `7.4` is already `END-OF-LIFE`,
because no patch level on that branch carries a fix. A version observed on a
blocked or error response is reported with low confidence and a caveat.

### 3b. Why a host can be `UNKNOWN`

Most modern sites hide `X-Powered-By` and do not expose the PHP patch level.
The scanner will not guess a version from a CMS name, a cookie or a marketing
page. If PHP is present but the version is hidden, the report says
`UNKNOWN` / `PHP present, version hidden` — not `YES` and not `NO`.

You can check the header yourself before scanning:

```sh
curl -sSI https://example.com/ | grep -i 'x-powered-by\|^server'
```

If the response contains `X-Powered-By: PHP/x.y.z`, the scanner can decide. If
it does not, the patch level has to come from the host or a diagnostic page
you are authorized to read. A `NO` would be a lie, so the tool does not print
one.

### 4. Verdicts

| Status | Meaning | Exposed? |
|---|---|---|
| `vulnerable` | Version is below the branch fix level | yes |
| `eol` | Branch has no upstream fix (5.x, 7.x, 8.0, 8.1) | yes |
| `patched` | At or above the branch fix level | no |
| `unknown` | PHP observed, version not established | unverified |
| `no_php` | No PHP markers on reachable paths; control behaved normally | no (scoped) |
| `inconclusive` | Blocked, auth wall, soft-404, rate limit, 5xx or unreachable | unverified |

Fix floors used by this release:

| Branch | First fixed release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Branches `5.x`, `7.x`, `8.0` and `8.1` are end-of-life for this bug class. A
branch newer than the table is `unknown` / `newer_than_table`, not guessed.

### 5. Exposure vs friction

`risk.score` is **exposure severity**, CVSS-shaped but not a CVSS vector:

- `vulnerable` → `9.8`
- `eol` → `10.0`
- `patched` / `no_php` → `0.0`
- unverified → `null` (`UNKNOWN`)

`risk.friction` is a separate, additive list of what an attacker would have to
beat: WAF, CDN, FPM worker affinity, auth wall, rate limit, edge block,
soft-404. A vulnerable interpreter behind a WAF is still a `9.8` exposure; the
WAF changes exploitation likelihood, not patch state.

`hackability` weighs the observed signals. When positive + negative evidence
is zero, `ratio` is `null` and the rating is `INCONCLUSIVE` — never `0.00` /
`NOT EXPOSED`. Each result also carries the decision a human can act on:
`answer` (`yes` / `no` / `unknown`, where `LIKELY` answers `yes` because the
burden is on disproving exposure) and `action` (the one sentence of advice
that follows from that answer). The JSON report exposes both fields under
`results.<target>.hackability`, and the text and Markdown reports print them
as the `DECISION` card.

### 6. ATT&CK and enrichment

The report always includes an **assessment path** (what this scan did and the
next low-risk verification steps). A **kill chain** is printed only when a
vulnerable interpreter is confirmed; printing one for an unconfirmed finding
trains people to ignore it.

Enrichment modules are pure functions of verdict + environment:

- `Detections` — WAF rules, PHP/FPM logs, worker health, EDR, origin exposure.
- `Remediation` — version-specific upgrade path, interim WAF controls, config
  audit, and the difference between a fix and compensation.
- `Tooling` — host-specific recommendations; offensive entries only with
  `--authorized`.
- `NextActions` — read-only commands (curl, openssl, dig) plus explicitly
  authorized follow-ups.
- `RedTeam` — attacker-perspective notes with `-r`.

### 7. Authorized POC

When a text-mode scan finds `vulnerable` or `eol`, the tool asks once:

```text
  AUTHORIZED PENETRATION TEST
  Detected PHP 8.4.26. The lab POC is calibrated for PHP 8.4.26 (bookworm).
  This host is exposed. Proceed with the authorized penetration test? [y/N]
```

`n` exits. `y` prints the authorized-use warning and runs the Ruby POC. There
is no POC flag. The POC reproduces the lab POC's wire behavior — raw HTTP/1.1,
multipart field layout, heap/library leak math, offsets, retries, worker
rotation and `out/p1` proof — but it is written in Ruby and isolated under
`lib/php2shell_poc2026/poc/`.

The POC is calibrated for the bookworm PHP 8.4.26 lab build, performs memory
exhaustion and worker rotation, and can disrupt the target. Machine-readable
formats, `--quiet` and non-interactive sessions cannot answer the question, so
they never run it. Every run ends with an explicit `RESULT: SUCCESS` or
`RESULT: FAILED`; `-v` adds the heap anchor, library base, carrier address,
`system()` address and the recorded output log. See
[docs/POC.md](docs/POC.md) for the full contract.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clear (patched / no PHP) or unverified without `--fail-on` |
| `1` | Usage, configuration or internal error |
| `2` | Exposed: vulnerable or end-of-life interpreter |
| `3` | Inconclusive, when `--fail-on inconclusive` or `--fail-on any` |
| `4` | Scope violation (`--require-scope`) |

`--fail-on` values:

- `exposed` (default): `2` only for exposure.
- `inconclusive`: `2` for exposure, `3` for any unverified target.
- `any`: same as `inconclusive` in this release; both mean "do not let a
  blocked result pass silently".
- `never`: always `0` unless there is an internal error.

A blocked host should fail a CI gate when you asked it to. That is the point.

The POC does not change the exit code. If the host is exposed, the process
still exits `2` whether the user answers `n`, the POC fails, or the POC
confirms code execution. The scan finding is the contract; the POC is an
additional evidence step.

---

## Output formats

| Format | Flag | Use |
|---|---|---|
| Text | `-f text` (default) | Human triage; `COLUMNS` aware |
| JSON | `-j`, `--json`, `-f json` | Full envelope, schema version `3.0` |
| Markdown | `-f markdown` | Tickets, bug bounty writeups, docs |
| SARIF | `-f sarif` | GitHub code scanning / security dashboards |
| CSV | `-f csv` | Spreadsheets and asset inventories |
| NDJSON | `-f ndjson` | Log shippers, streaming pipelines |

`--output FILE` writes to a file; `--output -` writes to stdout. `--compact`
makes JSON one line. `--evidence` adds a short body excerpt to JSON/NDJSON
probes (target-controlled data; use deliberately).

The JSON envelope is documented in [docs/JSON-SCHEMA.md](docs/JSON-SCHEMA.md).
Every format gets the same computed summary, so text, JSON and SARIF cannot
disagree about how many targets were exposed.

The POC is intentionally absent from JSON, Markdown, SARIF, CSV and NDJSON:
those formats have no terminal to answer the y/N question. It runs only in an
interactive text report. Use `--format text` on a TTY to see it.

---

## Command-line reference

```text
Usage: php2shell-poc2026 [options] URL [URL ...]
```

### Scanning

| Flag | Default | Description |
|---|---|---|
| `-p`, `--profile passive\|standard\|deep` | `standard` | Probe depth |
| `-d`, `--deep` | — | Alias for `--profile deep` |
| `-t`, `--timeout SECS` | `10` | Read timeout |
| `--connect-timeout SECS` | `5` | Connect/TLS timeout |
| `--max-redirects N` | `5` | Redirects per probe |
| `--max-body BYTES` | `512k` | Response cap (`512k`, `1M`) |
| `--retries N` | `1` | Retries for transient failures |
| `--no-retry-after` | — | Ignore `Retry-After` |
| `--delay MS` | `250` | Per-host minimum delay |
| `--threads N` | `4` | Target worker threads |
| `--max-requests N` | `25` | Per-target request budget |
| `--no-adaptive` | — | Probe even after a blanket denial |
| `--path PATH` | — | Extra path (repeatable) |

### HTTP

| Flag | Description |
|---|---|
| `-H`, `--header "Name: value"` | Extra header (repeatable) |
| `--cookie STRING` | Cookie header |
| `-A`, `--user-agent STRING` | User-Agent override |
| `--browser-ua` | Browser-compatible User-Agent for bot-protection compatibility (authorized only) |
| `--proxy URL` | HTTP proxy |
| `--no-proxy` | Ignore proxy environment variables |
| `--basic-auth USER:PASS` | Basic auth, same-origin only |
| `--bearer TOKEN` | Bearer token, same-origin only |
| `--ca-file PATH` | Custom CA bundle |
| `-k`, `--insecure` | Skip TLS verification (authorized self-signed only) |

### Scope and authorization

| Flag | Description |
|---|---|
| `--scope FILE` | Only scan hosts matching the scope file |
| `--exclude FILE` | Skip hosts matching the exclusion file |
| `--require-scope` | Fail closed (`4`) if a target is outside scope |
| `--authorized` | Include offensive/post-exploitation tooling entries |

The POC is not controlled by a flag. It is offered only after an exposed
text-mode scan and only after an explicit `y` answer. See
[docs/POC.md](docs/POC.md).

### Reporting

| Flag | Description |
|---|---|
| `-f`, `--format FORMAT` | `text`, `json`, `markdown`, `sarif`, `csv`, `ndjson` |
| `-j`, `--json` | Alias for `--format json` |
| `--lang LOCALE` | Text report language: `auto` (device language, default), `en` or `zh` |
| `-en` / `-zh` | Short forms of `--lang en` / `--lang zh` |
| `-o`, `--output FILE` | Write to a file; `-` means stdout |
| `--compact` | Compact JSON |
| `--no-banner` | Suppress the banner |
| `--no-color` | Disable colour (colour is automatic on a TTY; honours `NO_COLOR`) |
| `--evidence` | Body excerpt in JSON/NDJSON |
| `-q`, `--quiet` | Bottom line, findings table and run summary only (text) |
| `-r`, `--redteam` | Attacker notes |
| `-c`, `--toolchain` | Relevant tools |
| `--toolchain-full` | All tools with reasons |
| `-v`, `--verbose` | Technical details, attack-path notes, defender checks, all actions and the request trace |
| `--fail-on MODE` | `exposed`, `inconclusive`, `any`, `never` |
| `--dry-run` | Print the request plan; no socket |
| `-C`, `--config FILE` | YAML defaults |
| `-V`, `--version` | Version |
| `-h`, `--help` | Help |

---

## Profiles

| Profile | Requests (typical) | What it does |
|---|---|---|
| `passive` | 2 | Root + text canary; no `.php` probes |
| `standard` | 4 | Root + text/php canaries + `/index.php`; framework paths only if detected |
| `deep` | up to `--max-requests` | Common PHP paths, framework paths, `robots.txt`/`sitemap.xml` discovery |

Deep mode is still bounded by `--max-requests` and never brute-forces. It asks
for a handful of paths the site itself publishes.

---

## Scope files

Plain text, one pattern per line:

```text
# exact host and subdomains
example.com
# subdomains only
*.example.com
# single IP, CIDR, or URL
192.0.2.10
192.0.2.0/24
https://app.example.com
```

```sh
php2shell --scope scope.txt --require-scope https://app.example.com/
# exit 4 if the target is outside the list
```

Without `--require-scope`, out-of-scope targets are skipped with a warning and
the run continues. With it, the first out-of-scope target aborts before any
network traffic.

---

## Configuration file

```yaml
# php2shell.yml
profile: deep
format: sarif
output: reports/php2shell.sarif
delay_ms: 500
threads: 2
max_requests: 40
no_proxy: true
scope: scope.txt
require_scope: true
headers:
  X-Assessment: authorized
paths:
  - /health.php
targets:
  - https://example.com/
```

```sh
php2shell --config php2shell.yml
php2shell --config php2shell.yml https://other.example.com/   # CLI targets win
```

Relative `scope`, `exclude`, `ca_file` and `output` paths are resolved relative
to the config file. Unknown keys fail closed rather than being ignored.

---

## CI examples

```sh
# Fail on exposure only
php2shell --format sarif --output php2shell.sarif https://example.com/

# Fail on exposure or any blocked/unverified target
php2shell --fail-on inconclusive --format json https://example.com/
```

```yaml
- name: PHP2Shell triage
  run: |
    php2shell --scope scope.txt --require-scope \
      --fail-on inconclusive --format sarif \
      --output php2shell.sarif https://app.example.com/
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: php2shell.sarif
```

CI never runs the POC: the prompt requires an interactive terminal. A CI run
that finds an exposed host still fails with exit `2` and uploads the SARIF
report; it cannot answer the POC question.

---

## Safety properties

- **Scanner is GET-only.** No POST, no payloads, no fuzzing and no
  state-changing verbs during the scan itself.
- **POC is explicit and isolated.** The POST/multipart flow lives under
  `lib/php2shell_poc2026/poc/`, runs only after the exposed-host y/N prompt,
  and prints the authorized-use warning first.
- **Scanner is bounded.** `--max-requests`, body caps, redirect caps, retries
  and rate limits apply to the scan. The POC has its own fixed timeout,
  retries and 12 MB request bodies; it is not a scanner probe and is not
  covered by `--max-requests`.
- **Same-origin credentials.** `--cookie`, `--basic-auth` and `--bearer` are
  not forwarded across redirects to a different origin.
- **Scope enforced before I/O.** `--require-scope` exits `4` before the first
  socket.
- **Target data is untrusted.** Headers, titles, bodies and paths are
  sanitised for ANSI/OSC/control/bidi before they reach a terminal or a
  Markdown/CSV cell.
- **No silent scanning.** The User-Agent identifies the tool and the project
  by default.
- **Browser-UA mode is opt-in.** `--browser-ua` can cross a bot-control
  boundary, so it is never automatic, the report labels the mode, and the
  operator must confirm authorization first.
- **No automatic exploitation.** The POC is never started by a flag, a CI
  job or a machine-readable report. It requires an interactive exposed-host
  `y` answer and prints the warning before it runs.

---

## Project structure

```text
bin/                     php2shell
lib/php2shell_poc2026/
  cli.rb                 options, config, scope, threads, output, exit codes
  scanner.rb             adaptive orchestration, discovery, enrichment
  http_client.rb         Net::HTTP transport: redirects, retries, proxy, TLS
  probe.rb               one response + PHP/access evidence
  access.rb              blocked / restricted / soft-404 / auth-wall / 429
  verdict.rb             fix table and status decision
  risk.rb                exposure score + friction
  hackability.rb         signed evidence ratio (nil when no evidence)
  environment.rb         edge / CDN / WAF / hosting / SAPI / framework
  block_page.rb          OVHcloud/Cloudflare/Akamai/... block-page fingerprints
  poc/                   authorized raw-HTTP lab POC, after the y/N prompt
  report/                text, JSON, Markdown, SARIF, CSV, NDJSON
  scope.rb, target.rb, idn.rb, sanitize.rb, options.rb
  attack.rb, detections.rb, remediation.rb, tooling.rb, next_actions.rb
docs/                    methodology, JSON schema, authorized use, security
test/                    Minitest suite with fake transports and local TCP
```

---

## Development

```sh
bundle install
bundle exec rake test
ruby -Ilib bin/php2shell --dry-run https://example.com/
gem build php2shell_poc2026.gemspec
```

The test suite uses fake transports and a local TCP server; it does not scan
the internet and does not run the POC against a live target. POC helper tests
cover multipart bytes, cookie decoding, heap/library math, carrier layout,
offset parsing, consent and presentation in `test/poc_test.rb`.

---

## Documentation

- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — why the control probe exists,
  how evidence is weighed, and what each verdict means.
- [docs/POC.md](docs/POC.md) — the authorized POC contract, defaults, proof
  mechanism and limitations.
- [docs/JSON-SCHEMA.md](docs/JSON-SCHEMA.md) — the v3 JSON envelope.
- [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md) — scope, ROE and legal
  boundaries.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model and reporting.
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — code and test conventions.
- [docs/UML.md](docs/UML.md) — class, sequence and state diagrams.
- [README_zh.md](README_zh.md) — 简体中文 README.
- [CHANGELOG.md](CHANGELOG.md) — what changed in 3.0.

---

## License and disclaimer

MIT. See [LICENSE](LICENSE).

This tool produces an **indication**, not a certification. A `patched` result
covers the version evidence it saw; a `no_php` result covers the routes it
tested; an `inconclusive` result means exactly that. It is not a substitute
for host-side configuration review, authenticated testing under separate
authorization, or a real assessment by a human who understands the estate.

The POC is not a certification either. It is calibrated for the bookworm PHP
8.4.26 lab build, can disrupt the target, and its `out/p1` proof depends on a
shared lab volume or a command that writes somewhere you can read. A failed
POC does not prove the host is safe; a confirmed POC does not authorize you to
go further.

Only use it on systems you own or have explicit written permission to assess.
Do not use it against military, government, critical infrastructure or any
system outside your authorization. The authors and contributors accept no
liability for misuse, damage or legal consequences.
