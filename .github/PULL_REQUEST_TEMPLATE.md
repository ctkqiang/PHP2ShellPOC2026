## Summary

<!-- What problem does this change solve? Keep it short. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Report or schema change
- [ ] Localization
- [ ] Documentation
- [ ] CI, release or repository tooling
- [ ] Refactor with no behaviour change

## Scope and safety

- [ ] The scanner still sends only `GET` requests.
- [ ] The POC remains opt-in through the post-scan `y/N` prompt; no POC flag was added.
- [ ] Machine-readable formats, `--quiet`, `--output` and non-interactive sessions still cannot run the POC.
- [ ] Missing or blocked evidence is still reported as `UNKNOWN`, not as `NOT EXPOSED`.
- [ ] Scope is still enforced before the first socket is opened.
- [ ] Target-controlled text still passes through `Sanitize` before reaching a terminal or report cell.
- [ ] Tests do not scan the public internet or run the POC against a live third-party target.

## Verification

<!-- Paste the commands you ran and their results. -->

```sh
bundle exec rake test
ruby -Ilib bin/php2shell --version
```

- Test result:
- Exit code of the relevant CLI command:

## Interface changes

- [ ] Exit codes changed
- [ ] JSON schema changed
- [ ] CLI flags changed
- [ ] Report format changed
- [ ] None

<!-- If any box above is checked, describe the change and update the docs. -->

## Checklist

- [ ] I updated the relevant tests.
- [ ] I updated `CHANGELOG.md` for a user-visible change.
- [ ] I updated the README or `docs/` when behaviour or usage changed.
- [ ] I kept unrelated refactors out of this pull request.
- [ ] I have not included target secrets, credentials, cookies or personal data.
