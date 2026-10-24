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
- No POST or payloads during the scan itself.
- The authorized POC, only after an interactive exposed-host `y` answer:
  raw POST/multipart requests, memory exhaustion and worker rotation. It can
  disrupt the target and is calibrated for the bookworm PHP 8.4.26 lab build.

## What it does not authorize

- Bypassing a `403` by changing IP, proxy, Host header or User-Agent to evade
  a control. `--browser-ua` is for bot-protection compatibility where the
  program permits it, not for crossing an authorization boundary.
- Authenticated testing without separate authorization.
- Running the POC against military, government, critical infrastructure or any
  host outside your written authorization.
- Persistence, data exfiltration or lateral movement beyond the POC's
  `id>/out/p1` proof.
- Scanning an origin discovered behind a CDN unless the origin is in scope.
- Treating a `no_php` or `patched` result as permission to stop caring about
  the rest of the estate.

## The POC prompt

After the scan, if the verdict is `vulnerable` or `eol`, an interactive text
session asks:

```text
  AUTHORIZED PENETRATION TEST
  Detected PHP 8.4.26. The lab POC is calibrated for PHP 8.4.26 (bookworm).
  This host is exposed. Proceed with the authorized penetration test? [y/N]
```

Answering `n` exits. Answering `y` prints the authorized-use warning and runs
the POC. There is no POC flag. Machine-readable output, `--quiet`, `--output`
and non-interactive sessions cannot answer the question, so they never run it.

The POC writes `/out/p1` on the target and reads `./out/p1` locally; the lab
must share that directory. It uses a direct socket and fails closed if
`--proxy`, `--basic-auth`, `--bearer` or `--cookie` is set. Exit code `2`
still means the host is exposed even when the operator answers `n`.

If a target blocks the scanner, the report says `BLOCKED`. That is the correct
answer. Do not "fix" it by bypassing the block unless the program explicitly
authorizes that vantage point.

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
