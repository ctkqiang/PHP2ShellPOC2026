# Methodology

This document explains the decisions behind the 3.0 scan model. It is the
long-form version of the report's "why" — useful when a result is disputed,
when you are extending the tool, or when you need to explain to a reviewer why
a `403` is not a clean bill of health.

## The core problem: absence of evidence

A scanner can fail to observe PHP for many reasons:

- the edge blocks the scanner's IP, User-Agent or request shape;
- the site is behind a login;
- the server returns a catch-all page for every path;
- the origin is rate-limiting or unhealthy;
- the route simply is not PHP.

Only the last one is evidence about PHP. The first four are evidence about the
**access path**. The 2.x model collapsed all of them into "not hackable" and
printed a `0.00` ratio. That is the failure this release fixes.

## The control probe

For every target the scanner requests a random path that cannot exist:

```text
/php2shell-<8 random hex>.txt
/php2shell-<8 random hex>.php    (standard/deep profiles)
```

The control is compared with the root response. The comparison is deliberately
simple and conservative:

| Observation | Access state | Why |
|---|---|---|
| Root and control both `401/403/406/451` | `blocked` | The edge denied the scanner before the app answered |
| Root denied, control `404` | `restricted` | Path-level access control, not a blanket block |
| Control `2xx/3xx`, body/title near-identical to root | `soft_404` | Catch-all routing; path statuses are not trustworthy |
| Root redirects to / renders a login page | `auth_wall` | PHP may exist, but the surface is behind authentication |
| Root or control `429` | `rate_limited` | Throttling, not absence |
| Root `5xx` | `server_error` | Unhealthy app, not a patch verdict |
| Both error | `unreachable` | No usable application response |
| Root usable, control `404` | `open` | Path statuses can be read normally |

Similarity uses status, title, body length ratio and content type. A reflected
canary filename in the body is also treated as soft-404. The threshold is
intentionally conservative: a false soft-404 costs extra verification; a false
"open" would let path evidence lie.

## Block-page fingerprinting

A denial page is evidence about the edge, not the interpreter. The scanner
recognises common block pages (OVHcloud, Cloudflare, Akamai, Sucuri, Imperva,
AWS WAF, F5, Wordfence and ModSecurity) from headers, titles and visible body
text. The report names the vendor and the message, so a blanket `403` becomes
"OVHcloud blocked suspicious activity" instead of an anonymous dead end.

When the block is likely User-Agent-sensitive, the report offers an explicit
`--browser-ua` retry. That mode is opt-in, labelled in the report, and sends a
browser-compatible User-Agent. It is not automatic: a UA change can cross a
bot-control boundary, so it requires the same authorization check as any other
vantage-point change.

## Adaptive early exit

When access is `blocked`, `auth_wall`, `soft_404`, `rate_limited`,
`server_error` or `unreachable`, the scanner stops after the root and control
probes. Continuing to request `.php` paths would add noise, consume budget and
produce no new evidence about the interpreter.

`--no-adaptive` disables this. Use it when you have a specific reason to
enumerate paths despite a denial, and only within an authorized scope.

## Version evidence

Version is read from headers first, then `phpinfo()`. Header evidence is exact
when it is present; `phpinfo()` is authoritative but rare. A branch-only value
(`8.2`) is **not** promoted to a patch-level claim. It becomes
`unknown` / `branch_only` with the fix floor shown so an operator can compare
host-side. The exception is a branch-only value on an end-of-life branch
(`8.1`, `8.0`, `7.4`, …): no patch level on that branch carries a fix, so it
is reported as `eol` / exposed.

A version observed on a `403`, `5xx` or restricted response is still reported,
but with low confidence and an explicit caveat. A leaked version is useful
context, not a clean application assessment.

Framework versions (WordPress, Drupal, Joomla) are recorded separately. They
are never used to infer the PHP patch level.

## Verdict model

| Status | Evidence required | Exposed? |
|---|---|---|
| `vulnerable` | Patch-level version below the branch fix floor | yes |
| `eol` | Branch has no upstream fix for this bug class | yes |
| `patched` | Patch-level version at or above the fix floor | no |
| `unknown` | PHP observed, version absent or branch-only | unverified |
| `no_php` | No PHP markers on tested paths; control behaved normally | no, scoped |
| `inconclusive` | Access/evidence state prevents an assessment | unverified |

The fix table is:

| Branch | First fixed release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Branches `5.x`, `7.x`, `8.0` and `8.1` are treated as end-of-life. A branch
newer than the table is `unknown` / `newer_than_table`; the tool does not guess.

## Exposure versus friction

Two different questions were previously folded into one score:

1. **How bad is it if the interpreter is vulnerable?** (`risk.score`)
2. **How hard would exploitation be?** (`risk.friction`)

The exposure score is CVSS-shaped but is not a CVSS vector:

- `vulnerable` → `9.8`
- `eol` → `10.0`
- `patched` / `no_php` → `0.0`
- unverified → `null` / `UNKNOWN`

Friction is additive and separate:

- WAF in front
- CDN masking the origin
- FPM worker affinity
- Auth wall
- Rate limiting
- Blanket edge block
- Soft-404 routing

A WAF does not make a vulnerable parser patched. It changes the likelihood and
reliability of exploitation. A CDN does not reduce exposure severity; it
changes where the origin is and whether edge rules are the only control.

## The decision answer

The evidence rating is not the answer a decision-maker needs. Every result
therefore also carries `hackability.answer`:

- `yes` — a vulnerable or end-of-life interpreter was observed, or exposure
  signals dominate enough that the host must be treated as hackable;
- `no` — the interpreter meets the fix level, or no PHP surface was observed
  on the probed paths;
- `unknown` — the evidence is missing, blocked or only branch-level.

`hackability.action` is the single sentence that follows from that answer.
The text report puts the answer above the findings table and repeats it in
the per-target `DECISION` card, so a reader can stop after the first lines.
`unknown` is never rendered as `no`: a blocked or unversioned host is not
evidence of a patched one.

## Hackability ratio

`hackability` is a signed evidence ratio, not a probability:

- Positive signals: vulnerable/EOL version, PHP markers, PHPSESSID,
  phpinfo exposure, verbose errors, live `.php` route, framework.
- Negative signals: patched version, no PHP markers.
- Neutral signals: blocked edge, soft-404, branch-only version, WAF/CDN/FPM
  friction.

When `positive + negative == 0`, `ratio` is `null` and the rating is
`INCONCLUSIVE`. This is deliberate: `0.00` would imply negative evidence that
does not exist.

## ATT&CK mapping

The report has two ATT&CK layers:

- **Assessment path** — the Reconnaissance techniques the scan performed
  (`T1595` active scanning, `T1592` host information) and the next low-risk
  verification steps (certificate transparency, host-side version read,
  approved egress).
- **Kill chain** — only printed when a vulnerable interpreter is confirmed:
  `T1190` initial access, `T1059.004` Unix shell execution, `T1505.003` web
  shell persistence, `T1005` local data collection, `T1082` discovery,
  `T1071.001` web C2.

Printing a kill chain for an unconfirmed finding trains readers to ignore it.
The scanner therefore keeps the two layers separate.

## Discovery

Deep mode is not a directory brute-forcer. It reads `robots.txt`, follows a
same-host `Sitemap:` entry (or `/sitemap.xml`), and requests at most five
same-host `.php` paths published by the site. Unsafe paths (logout, delete,
checkout, admin-ajax, etc.) are filtered out. Everything is bounded by
`--max-requests`.

## What the tool does not do

- No POST, PUT, PATCH or DELETE.
- No exploit payloads, fuzzing, malformed multipart bodies or parser stress.
- No authentication bypass, WAF evasion or rate-limit evasion.
- No directory brute-forcing.
- No claim that a `no_php` result covers the whole estate.
- No claim that a `patched` result covers configuration or application bugs.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618)
- [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
- [PHP release notes](https://www.php.net/releases/)
- [docs/AUTHORIZED-USE.md](AUTHORIZED-USE.md)
