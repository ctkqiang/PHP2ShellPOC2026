# PHP2ShellPOC2026 — architecture

Three views of the 3.0 system. All diagrams are Mermaid and render on GitHub.

- [Scan sequence](#scan-sequence) — what happens for one target
- [Class map](#class-map) — what exists and who owns policy
- [Verdict state machine](#verdict-state-machine) — how evidence becomes a status

---

## Scan sequence

```mermaid
sequenceDiagram
    participant CLI
    participant Scope
    participant Scanner
    participant HTTP as HttpClient
    participant Access
    participant Verdict
    participant Report

    CLI->>Scope: include?(target)
    alt out of scope and --require-scope
        Scope-->>CLI: denied
        CLI-->>CLI: exit 4 before I/O
    else in scope
        CLI->>Scanner: scan(target, scope_decision)
        Scanner->>HTTP: GET / (root)
        Scanner->>HTTP: GET /php2shell-<hex>.txt
        Scanner->>HTTP: GET /php2shell-<hex>.php
        Scanner->>Access: classify(root + controls)
        alt blocked / auth wall / soft-404 / 429 / 5xx / unreachable
            Access-->>Scanner: inconclusive access
            Note over Scanner: adaptive stop
        else open or restricted
            Scanner->>HTTP: GET /index.php + framework paths
            opt deep and root usable
                Scanner->>HTTP: GET /robots.txt, /sitemap.xml
                Scanner->>HTTP: GET discovered .php paths
            end
        end
        Scanner->>Verdict: assess(version, surface, access)
        Scanner->>Scanner: environment, risk, hackability, enrichment
        Scanner-->>CLI: ScanResult
        CLI->>Report: render(results, options, summary)
        Report-->>CLI: text / JSON / Markdown / SARIF / CSV / NDJSON
        CLI-->>CLI: exit 0/2/3 (1 on internal error)
    end
```

The key ordering: **scope before socket**, **control before trusting status
codes**, **access before version**, **exposure before friction**, **kill chain
only after confirmed exposure**.

---

## Class map

```mermaid
classDiagram
    class CLI {
        +run() Integer
        -parse_options!()
        -load_config(path)
        -enforce_scope(targets, scope, exclude)
        -scan_all(work) ScanResult[]
        -exit_code(results) Integer
    }

    class Scanner {
        +scan(target, scope_decision) ScanResult
        +plan(target, scope_decision) Hash
        -fetch_controls(client, target)
        -main_paths_for(target, probes)
        -discover_paths(client, target, probes, trace)
        -extract_version(probes)
        -surface_of(probes, access, frameworks)
    }

    class HttpClient {
        +get(uri, follow_redirects, purpose) Probe
        +requests Integer
        +exhausted? Boolean
        -fetch_once(uri)
        -perform_with_retries(uri)
        -resolve_proxy()
    }

    class Probe {
        +status Integer
        +headers Hash
        +body String
        +php_version_from_headers()
        +php_version_from_phpinfo()
        +php_cookie?()
        +php_fpm_not_found?()
        +similarity_to(other) Float
    }

    class Access {
        +state Symbol
        +reason String
        +control Hash
        +classify(probes, root) Access
    }

    class Verdict {
        +status Symbol
        +reason_code Symbol
        +version Gem::Version
        +branch String
        +fix_floor Gem::Version
        +assess(version, surface, access) Verdict
        +exposed? Boolean
    }

    class Risk {
        +score Float
        +grade String
        +friction Hash
        +assess(verdict, environment) Hash
    }

    class Hackability {
        +rating Symbol
        +ratio Float
        +signals Signal[]
        +assess(verdict, environment, risk, coverage) Result
    }

    class Environment {
        +server String
        +edge String
        +cdn String
        +waf String
        +sapi String
        +frameworks Detection[]
    }

    class ScanResult {
        +target Target
        +verdict Verdict
        +environment Environment
        +risk Hash
        +hackability Result
        +probes Probe[]
        +to_h(include_body) Hash
    }

    class Report {
        +render(results, options, meta) String
        +summary(results, options, meta) Hash
    }

    class Scope {
        +include?(target) Decision
        +load(path) Scope
    }

    CLI --> Scanner
    CLI --> Scope
    CLI --> Report
    Scanner --> HttpClient
    HttpClient --> Probe
    Scanner --> Access
    Scanner --> Verdict
    Scanner --> Risk
    Scanner --> Hackability
    Scanner --> Environment
    Scanner --> ScanResult
    ScanResult --> Report
```

Policy lives in the decision modules, not in `Scanner`:

- `Access` decides what the edge did.
- `Verdict` decides what the version means.
- `Risk` decides exposure severity and friction separately.
- `Hackability` weighs evidence and returns `nil` when there is none.
- `Report` never sees an HTTP response, only a `ScanResult`.

---

## Verdict state machine

```mermaid
stateDiagram-v2
    [*] --> Access

    state Access {
        [*] --> Open: root usable, control 404
        [*] --> Blocked: root + control denied
        [*] --> Restricted: root denied, control 404
        [*] --> AuthWall: root login/redirect
        [*] --> Soft404: control mirrors root
        [*] --> RateLimited: 429
        [*] --> ServerError: 5xx
        [*] --> Unreachable: errors
    }

    Access --> Inconclusive: blocked / auth / soft404 / 429 / 5xx / unreachable
    Access --> VersionCheck: open or restricted

    state VersionCheck {
        [*] --> NoVersion
        [*] --> PatchLevel
        [*] --> BranchOnly
    }

    NoVersion --> NoPHP: no PHP markers
    NoVersion --> Unknown: PHP markers
    BranchOnly --> Unknown
    PatchLevel --> Vulnerable: below floor
    PatchLevel --> Patched: at/above floor
    PatchLevel --> EOL: 5.x/7.x/8.0/8.1
    PatchLevel --> Unknown: newer than table

    Vulnerable --> [*]
    EOL --> [*]
    Patched --> [*]
    NoPHP --> [*]
    Unknown --> [*]
    Inconclusive --> [*]
```

`Inconclusive` is a terminal state, not a failure to be retried silently. It
means the scan could not produce usable application evidence; the next step is
host-side verification or an approved vantage point, not a claim of safety.
