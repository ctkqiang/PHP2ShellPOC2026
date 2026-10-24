# Contributing

Thanks for helping improve php2shell-poc2026. The project is intentionally
small, dependency-free and conservative about what it sends.

## Ground rules

- **No exploit code.** This repository is a passive triage tool. Do not add
  payloads, fuzzers, authentication bypasses, WAF evasion or state-changing
  requests.
- **No unbounded scanning.** New probes must respect `--max-requests`,
  `--delay`, `--threads` and the adaptive early-exit model.
- **Evidence first.** A new verdict or signal needs a test with a fake
  response that demonstrates the evidence, not just a code path.
- **Honesty over optimism.** If the scanner cannot see the application, the
  result must say so. Do not turn missing evidence into a clean verdict.
- **Sanitise target data.** Anything from a response that reaches a terminal,
  Markdown, CSV or JSON must go through `Sanitize`.

## Setup

```sh
git clone https://github.com/ctkqiang/PHP2ShellPOC2026.git
cd PHP2ShellPOC2026
bundle install
bundle exec rake test
```

Ruby `>= 2.7` is supported. The test suite uses only the standard library,
Minitest and a local TCP server; it must not scan the internet.

## Tests

```sh
bundle exec rake test
ruby -Ilib:test test/scanner_test.rb
```

Coverage expectations for a change:

- scanner/access change: a fake-transport test in `test/scanner_test.rb`;
- transport change: a local-server test in `test/http_client_test.rb`;
- report change: a format test in `test/report_test.rb`;
- CLI/scope/config change: a dry-run test in `test/cli_test.rb`;
- parsing/IDN/scope change: a unit test in the relevant `*_test.rb`.

Tests must not depend on external DNS, the public internet, or the current
date/time.

## Style

- Ruby standard library only at runtime.
- Prefer small, pure modules for enrichment (verdict/environment in, records
  out).
- Keep `Scanner` as orchestration; do not put rendering or policy in it.
- Comments explain *why*, not *what*.
- No trailing whitespace; two-space indentation; frozen string literals.

## Adding a probe

1. Add the path to the appropriate profile list or discovery module.
2. Respect `Discovery.safe_path?` and the request budget.
3. Add a fake response in `test/scanner_test.rb`.
4. Update `docs/METHODOLOGY.md` if the probe changes the access or verdict
   model.
5. Do not add a probe that changes state, logs a user out, or triggers a
   destructive action.

## Adding a report format

1. Implement `Report::YourFormat.render(results, options, summary:, meta:)`.
2. Require it from `lib/php2shell_poc2026/report.rb`.
3. Add it to `Options::FORMATS`, `Report::FORMATS` and the CLI help.
4. Add a test in `test/report_test.rb`.
5. Keep the shared `Summary` numbers identical across formats.

## Pull requests

- Describe the problem, the change and the evidence.
- Include the commands you ran and their exit codes.
- Note any change to exit codes, JSON schema or CLI flags; those are interface
  changes.
- Keep unrelated refactors out of a bug-fix PR.

## License

By contributing, you agree that your contribution is licensed under the MIT
License (see [LICENSE](../LICENSE)).
