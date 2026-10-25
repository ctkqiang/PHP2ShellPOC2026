# Security policy

This repository is a security assessment tool. Its own code and dependencies
are in scope for security reports; third-party targets are not.

## Supported versions

| Version | Supported |
|---|---|
| 3.x | yes |
| 2.x and older | no |

## Report a vulnerability privately

Please use GitHub's private vulnerability reporting:

**https://github.com/ctkqiang/PHP2ShellPOC2026/security/advisories/new**

Do not open a public issue for a vulnerability in this tool. If private
reporting is unavailable, contact the maintainer through the repository
profile and ask for a private channel before sharing details.

Include, where possible:

- the version (`php2shell --version`);
- Ruby version and operating system;
- the command line, with credentials, cookies and target names redacted;
- a minimal reproduction or fixture;
- observed and expected behaviour;
- the security impact you believe is possible.

Do not include live target secrets, session cookies, personal data or
third-party data in the report. Redact aggressively.

## Scope

In scope:

- credential leakage or cross-origin credential forwarding;
- scope bypass or a path that opens a socket before scope enforcement;
- terminal escape, control-character or bidi injection through target data;
- Markdown/CSV/JSON injection that survives sanitisation;
- POC path traversal, command injection, or unintended network egress;
- dependency or build-chain compromise.

Out of scope for this repository:

- vulnerabilities in a third-party PHP installation or website;
- the PHP2Shell bug itself in someone else's system;
- unauthorized testing of systems you do not own.

If you find a vulnerability in a third-party target, follow that program's
disclosure process. The project cannot authorize testing on your behalf.

## Safe testing

Only test against systems you own or have explicit written permission to
assess. The POC can perform memory exhaustion and worker rotation, and it can
disrupt a target. A failed POC is not evidence that a target is patched.

See [docs/SECURITY.md](../docs/SECURITY.md) for the full threat model and
[docs/AUTHORIZED-USE.md](../docs/AUTHORIZED-USE.md) for authorization
requirements.
