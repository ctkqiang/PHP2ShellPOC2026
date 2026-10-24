# Security policy

## Reporting a vulnerability in this tool

If you find a security issue in php2shell-poc2026 itself — a way to make the
scanner leak credentials, execute target content, escape the terminal
sanitiser, or bypass scope — please report it privately to the maintainers
before opening a public issue.

Include:

- the version (`php2shell --version`),
- the command line (redact credentials),
- a minimal target or fixture that reproduces it,
- the observed and expected behaviour.

Do not include live target secrets, session cookies or personal data in a
public report.

## Threat model

The scanner treats **everything from the target as untrusted**:

- status lines, headers, titles, bodies, cookies, redirects, TLS certificate
  fields, DNS answers and sitemap/robots content;
- target-supplied text can contain ANSI/OSC escapes, control characters,
  bidi overrides, zero-width characters, CR/LF, Markdown/CSV delimiters and
  enormous strings.

Mitigations:

- `Sanitize.terminal` strips ANSI/OSC, control and bidi characters and
  collapses whitespace before text reaches a terminal.
- Markdown cells escape pipes; CSV fields are quoted.
- Header values are stripped of CR/LF before being sent; response headers are
  never reflected into a request.
- Response bodies are capped (`--max-body`) and decoded with a charset-aware
  scrubber.
- Redirects are limited and only `http(s)` is followed.
- Credentials are only attached to same-origin requests.
- `--require-scope` fails before any socket is opened.
- Body excerpts are opt-in (`--evidence`) and remain target-controlled data.

## POC output

The POC proof and journal are target-controlled data. They are sanitised with
`Sanitize.terminal` before printing. The POC runs only after the interactive
exposed-host `y` answer; it never runs from JSON/SARIF/CSV/NDJSON, `--quiet`,
or a non-interactive session. The POC uses a direct socket and fails closed if
`--proxy`, `--basic-auth`, `--bearer` or `--cookie` is set.

## Credentials

- Prefer a dedicated, least-privilege credential for authorized authenticated
  checks.
- `--cookie`, `--basic-auth` and `--bearer` are redacted in `options` output.
- Do not put credentials in a URL; the target parser rejects them.
- Be careful with `-v`: traces include URLs and response metadata, not
  request credentials, but target content may still be sensitive.

## Scope

`--scope` accepts exact hosts, subdomains, wildcards, IPs, CIDRs and URLs.
`--require-scope` turns a mismatch into exit code `4` before scanning. Without
it, mismatches are skipped with a warning. Scope is not a substitute for
reading the program's rules.

## Dependencies

The gem has no runtime dependencies; it uses the Ruby standard library only.
Development dependencies are `minitest` and `rake`. Keep it that way unless
there is a compelling reason and a security review.
