# Authorized POC

The POC is a Ruby translation of the lab PHP2Shell exploit. It is not part of
the passive scanner. It runs only after an interactive text-mode scan has
found an exposed host and the operator has answered the single y/N question.

## Warning

This POC is for authorized lab or engagement use only. It performs memory
exhaustion and worker rotation. It can disrupt the target service. It is
calibrated for the bookworm PHP 8.4.26 build; another build may fail or behave
unexpectedly.

Do not use it against military, government, critical infrastructure or any
system you do not own or have explicit written permission to test.
Unauthorized access is illegal. The authors and contributors accept no
liability for misuse, damage or legal consequences.

## No POC flag

There is no `--poc`, `--exploit` or POC configuration flag. The only interface
is the post-scan question:

```text
  AUTHORIZED PENETRATION TEST
  Detected PHP 8.4.26. The lab POC is calibrated for PHP 8.4.26 (bookworm).
  This host is exposed. Proceed with the authorized penetration test? [y/N]
```

- `n` exits without sending POC traffic.
- `y` prints the full warning and runs the POC.
- `patched`, `no_php`, `unknown` and `inconclusive` never ask.
- JSON, SARIF, CSV, NDJSON, `--quiet`, `--output` and non-interactive sessions
  cannot answer the question, so they never run the POC.

## Language

The POC is text-only, so its prompt, warning, progress lines and result card
follow the same language as the text report: `--lang`, `-en`/`-zh`, the
device locale and the usual `PHP2SHELL_LANG`/`LC_*`/`LANG` variables. The
technical offsets are shown only with `-v`. Machine formats never run the POC.

## Result card

Every run ends with an explicit `RESULT: SUCCESS` or `RESULT: FAILED` line.
Without `-v` the card shows the proof (or the plain-language failure reason),
retry counts and duration. With `-v` it also prints the technical diagnostics —
status, error code, heap anchor, library base, carrier address and `system()`
address — followed by the recorded output log, one line per event.

## Defaults

| Setting | Value |
|---|---|
| Profile | `bookworm` (PHP 8.4.26 lab) |
| Command | `id>/out/p1` (14-byte carrier limit) |
| Proof file | `out/p1` relative to the current directory |
| Offsets file | `out/offsets.env` relative to the current directory |
| OOM field | 12 MB |
| Per-request timeout | 30 s (90 s for warm-up requests) |
| Heap/library retries | 3 each |
| Command retries | 5 |
| Worker rotation | Before each phase and after failed attempts |

There is no fetch flag, no proof-path flag and no Docker auto-offset helper.
If `out/offsets.env` is absent, the bookworm/lab constants are used.

## Offsets file

The file is optional. It uses the lab helper's simple format:

```text
ZIF_OFFSET=0x43a870
DTOR_OFFSET=0x613c50
HTDATA_OFFSET=0x690d8
```

Unknown keys and malformed values are ignored. The values are specific to the
target's `libphp` build; they are not portable across PHP versions, distro
builds, Apache/LiteSpeed, or ASLR layouts.

## What the POC sends

- Raw HTTP/1.1 over `Socket` and OpenSSL, not `Net::HTTP`.
- `POST` multipart bodies with the exact field counts, names, boundaries and
  byte layout required by the lab exploit.
- A 12 MB `big` field to exhaust the worker's memory limit.
- 1001 small parts to shape the heap, plus the session and upload-progress
  fields.
- Worker rotation between phases and after failed attempts.
- A raw `GET` only if a future proof mechanism requires it; the current
  default uses the local `out/p1` file.

The POC does not forward `--proxy`, `--basic-auth`, `--bearer` or `--cookie`;
it fails closed with an error if any of those are set. It uses the existing
TLS settings (`--insecure`, `--ca-file`) for its direct connection.

## Proof

The default command is:

```text
id>/out/p1
```

The target writes `/out/p1`; the lab maps that directory to `./out/p1` in the
scanner's working directory. The POC reads and strips that file. If the lab
does not share the directory, the command may execute but the POC will report
`FAILED` because it has no proof.

A failed POC is not evidence that the host is safe. A confirmed POC is
evidence of code execution on that build; it does not authorize further
access, persistence or data collection.

## Machine-readable formats

The POC is deliberately not represented in the JSON/SARIF/CSV/NDJSON
envelope. Those formats are non-interactive and cannot show the warning or
ask the question. Use `--format text` on a TTY to see the POC prompt and
result.

## Exit codes

The POC does not change the scan exit code:

- exposed host: `2`, whether the user answers `n`, the POC fails, or the POC
  confirms execution;
- patched/no PHP: `0`;
- unverified: `0` by default, `3` with `--fail-on inconclusive|any`;
- usage/scope/internal errors follow the scanner's existing codes.

## Tests

`test/poc_test.rb` covers the deterministic pieces: multipart bytes, cookie
percent-decoding, heap/library anchor arithmetic, carrier layout, offset file
parsing, consent and presentation, plus a local TCP test for the raw
transport. The full exploit is not run against a live target in the test
suite.
