# Authorized use

This tool is built for authorized security work: internal asset inventories,
bug bounty programs whose scope explicitly permits it, purple-team exercises,
and host owners checking their own deployments.

It is not a permission slip. Running it against a host you do not own or have
written permission to assess may violate computer-misuse law, the target's
terms of service, or both.

## Before the first request

1. **Read the program scope.** Note which hosts, ports, paths and schemes are
   in scope. A parent domain in scope does not automatically put every
   subdomain in scope.
2. **Read the rules of engagement.** Some programs forbid automated scanning,
   rate limits, or specific paths. Follow the stricter rule.
3. **Set a scope file.** Use `--scope` and `--require-scope` so the process
   fails closed before it opens a socket:

   ```sh
   php2shell --scope scope.txt --require-scope https://app.example.com/
   ```

4. **Plan first.** `--dry-run` prints every request without sending it.
5. **Choose a rate the target can tolerate.** `--delay`, `--threads` and
   `--max-requests` are there for a reason.
6. **Know your data handling.** Reports can contain target-controlled text,
   headers, certificate details and optional body excerpts. Store them
   accordingly.

## What this tool sends

- Ordinary `GET` requests.
- A small, bounded set of paths (root, canaries, `/index.php`, common PHP
  names, framework paths, `robots.txt`, `sitemap.xml`).
- A User-Agent that identifies the tool and project by default.
- `--browser-ua` only when you explicitly ask for it: a browser-compatible
  User-Agent for hosts whose bot protection rejects the identifying string.
  It is not automatic and it is not a licence to bypass an authorization
  boundary.
- No POST, no payloads, no fuzzing, no authentication bypass, no rate-limit
  evasion.

## What it does not authorize

- Bypassing a `403` by changing IP, proxy, Host header or User-Agent to evade
  a control. `--browser-ua` is for bot-protection compatibility where the
  program permits it, not for crossing an authorization boundary.
- Authenticated testing without separate authorization.
- Exploitation, persistence, data exfiltration or lateral movement.
- Scanning an origin discovered behind a CDN unless the origin is in scope.
- Treating a `no_php` or `patched` result as permission to stop caring about
  the rest of the estate.

If a target blocks the scanner, the report says `BLOCKED`. That is the correct
answer. Do not "fix" it by bypassing the block unless the program explicitly
authorizes that vantage point.

## Automated follow-up

After a text report, the scanner can ask whether to run safe follow-up checks:
a fresh response, the captured TLS/DNS data and a SARIF export. These are
read-only and stay on the same target.

A browser-compatible retry and active tools such as `nuclei` require
`--authorized`. The prompt is a convenience, not a permission slip: the
program scope and rules of engagement still decide whether either is allowed.

## Bug bounty notes

- Use the program's provided scope and rate limits; do not import a generic
  subdomain list into `--scope` without checking it.
- Keep the `--dry-run` plan and the final report as evidence of what you sent.
- A `403` is not a finding by itself. It is a reason to verify from an
  approved vantage point or host-side.
- A leaked version on a block page is useful context, but do not claim
  exploitability without a reproducible, authorized test.
- If you find a real vulnerability, follow the program's disclosure process.
  Do not paste target secrets into a public report.

## Legal

This document is not legal advice. Authorization requirements vary by
jurisdiction and by contract. When in doubt, ask the asset owner in writing
and keep the answer.
