# PHP2ShellPOC2026 — UML diagrams

Four views of the system, each answering a different question. All diagrams
are Mermaid and render natively on GitHub.

- [Class diagram](#class-diagram) — what exists, and how it relates
- [Scan sequence](#scan-sequence) — what happens, in order, for one target
- [Verdict state machine](#verdict-state-machine) — how a target reaches a verdict
- [Rendering flow](#rendering-flow) — how a ScanResult becomes output

---

## Class diagram

Everything in the system, grouped by role. The left column is the evidence
objects the scan produces evidence *with*; the centre is the scanner that
orchestrates them; the right column is enrichment — four independent modules
that each read the verdict and environment and contribute a section of the
report. Structs are marked `<<Struct>>`; they are plain data records with no
behaviour of their own beyond `to_h`.

Notable design points:

- **`Verdict` owns classification policy** (`FIXED_RELEASES`, `assess`), not
  the scanner — the scanner asks for a verdict, it does not decide what one
  means. Everything downstream keys off `exposed?`.
- **`ScanResult` is the handoff type** between scanning and presentation.
  `Report` never sees a `Probe` or an HTTP response, only a `ScanResult`.
- **Enrichment modules are pure**: verdict and environment in, records out.
  None of them performs I/O, which is why they are trivially testable and
  why adding a fifth one cannot break scanning.
- **`Hackability` weighs, it does not decide**: it turns observed signals
  into a signed ratio and a rating, but its clamps (no PHP observed ⇒ never
  above NOT HACKABLE, unconfirmed fingerprint ⇒ never above LIKELY) mean the
  number can only ever be as confident as the evidence underneath it. Risk
  answers "how bad if true"; Hackability answers "how sure are we, now".

```mermaid
classDiagram
    class Verdict {
        <<class>>
        +Symbol status
        +Gem::Version version
        +String version_source
        +String reason
        +Hash attack_surface
        +Hash FIXED_RELEASES
        +assess(version, attack_surface, version_source) Verdict
        +exposed? Boolean
        +to_h Hash
    }

    class Probe {
        <<class>>
        +URI uri
        +Hash headers
        +Integer status
        +String body
        +php_powered_by String
        +session_cookie? Boolean
        +php_error_page? Boolean
        +version_from_phpinfo String
        +php_endpoint? Boolean
    }

    class Environment {
        <<class>>
        +String server
        +String cdn
        +String waf
        +String sapi
        +String sapi_rationale
        +cdn? Boolean
        +to_h Hash
        -detect_cdn headers
        -detect_waf headers
        -detect_sapi headers
    }

    class Scanner {
        <<class>>
        +Integer timeout
        +Boolean verify_tls
        +Boolean deep
        +Boolean verbose
        +scan(target) ScanResult
        -normalize(target) URI
        -fetch(uri) Probe
        -extract_version(probes) Version
        -surface_of(probes) Hash
        -trace(line)
    }

    class ScanResult {
        <<Struct>>
        +String target
        +Verdict verdict
        +Environment environment
        +Hash risk
        +Technique[] attack_chain
        +Layer[] detections
        +String[] red_team
        +Entry[] tooling
        +Hash fingerprint
        +Result hackability
        +String[] remediation
        +String[] trace
        +exposed? Boolean
        +to_h Hash
    }

    class Risk {
        <<module>>
        +Hash BASE
        +assess(verdict, environment) Hash
        +grade(score) String
        -apply_sapi(base, verdict, environment) Float
    }

    class Hackability {
        <<module>>
        +Hash RATINGS
        +assess(verdict, environment) Result
        +rate(ratio, verdict, surface) Symbol
        +build_signals(verdict, environment, surface) Signal[]
        +prerequisites(verdict, environment, surface) String[]
        +reliability(verdict, environment) String
        +impact(verdict) String
    }

    class Signal {
        <<Struct>>
        +Symbol direction
        +Integer weight
        +String label
    }

    class Result {
        <<Struct>>
        +Symbol rating
        +String label
        +Float ratio
        +Integer positive
        +Integer negative
        +String[] prerequisites
        +String reliability
        +String impact
        +Signal[] signals
        +hackable? Boolean
        +to_h Hash
    }

    class Remediation {
        <<module>>
        +for(verdict, environment) String[]
        +vulnerable(verdict, environment) String[]
        +eol(verdict, environment) String[]
        +patched(verdict) String[]
        +unconfirmed String[]
        +edge_steps(environment) String[]
    }

    class Layout {
        <<module>>
        +width Integer
        +wrap(text, limit) String[]
        +wrap_hanging(prefix, text) String[]
        +truncate(text, limit) String
        +table(headers, rows) String[]
        -terminal_width Integer
        -greedy(text, limit) String[]
        -chunk(line, limit) String[]
        -shrink(naturals, usable) Integer[]
        -stacked(headers, rows) String[]
    }

    class Attack {
        <<module>>
        +techniques_for(verdict) Technique[]
    }

    class Technique {
        <<Struct>>
        +String id
        +String name
        +String tactic
        +String applies
        +String note
    }

    class Detections {
        <<module>>
        +for(verdict, environment) Layer[]
        +exposure_layers Layer[]
        +origin_layer(environment) Layer
        +config_layer Layer
    }

    class Layer {
        <<Struct>>
        +String layer
        +String control
        +String detail
    }

    class RedTeam {
        <<module>>
        +notes(verdict, environment) String[]
    }

    class Tooling {
        <<module>>
        +catalogue(verdict, environment) Entry[]
        +core Entry[]
        +origin_discovery(environment) Entry
        -entry(phase, tool, purpose, relevance, techniques) Entry
    }

    class Entry {
        <<Struct>>
        +String phase
        +String tool
        +String purpose
        +String relevance
        +String[] techniques
    }

    class Report {
        <<module>>
        +json(results) String
    }

    class Text {
        <<class>>
        +Boolean redteam
        +Boolean toolchain
        +Boolean verbose
        +render()
        -summary(target, result)
        -attack_chain(result)
        -detections(result)
        -red_team(result)
        -toolchain(result)
        -trace(result)
    }

    class CLI {
        <<class>>
        +String[] argv
        +Integer run()
        -parse_options!()
        -scan_all(scanner) Hash
    }

    Scanner --> Probe : constructs per request
    Scanner --> Environment : builds from first probe
    Scanner --> Verdict : assess
    Scanner --> ScanResult : returns
    Risk --> Verdict : reads status
    Risk --> Environment : reads sapi / cdn
    Hackability --> Verdict : reads
    Hackability --> Environment : reads
    Hackability --> Signal : produces
    Hackability --> Result : builds
    ScanResult *-- Result
    Remediation --> Verdict : reads
    Remediation --> Environment : reads
    Text --> Layout : measures width
    Attack --> Technique : produces
    Detections --> Layer : produces
    Tooling --> Entry : produces
    Attack --> Verdict : reads
    Detections --> Verdict : reads
    RedTeam --> Verdict : reads
    Tooling --> Verdict : reads
    ScanResult *-- Verdict
    ScanResult *-- Environment
    CLI --> Scanner : one scan per target
    CLI --> Report : renders through
    Report --> Text
    Text --> ScanResult : reads
```

## Scan sequence

What actually happens for a single target, including the failure path: a
probe that cannot be completed comes back `nil`, the usable set shrinks, and
classification proceeds on whatever evidence survived — which is exactly how
a reachable host with one dead path still gets a real verdict.

```mermaid
sequenceDiagram
    actor Operator
    participant CLI
    participant Scanner
    participant NetHTTP as Net HTTP client
    participant Probe
    participant Env as Environment
    participant Verdict
    participant Risk
    participant Hackability
    participant Enrich as Attack / Detections / RedTeam / Tooling
    participant Report

    Operator->>CLI: URL(s) + flags
    CLI->>CLI: parse_options! validate flags
    loop one pass per target
        CLI->>Scanner: scan(target)
        Scanner->>Scanner: normalize URL
        par root probe (+ deep paths if --deep)
            Scanner->>NetHTTP: GET (timeout, TLS verify, UA)
            NetHTTP-->>Scanner: response or error
        end
        alt response received
            Scanner->>Probe: wrap headers / status / body
            Probe-->>Scanner: version signals, cookie, errors, endpoint?
        else request failed
            Scanner-->>Scanner: probe = nil, warn, keep going
        end
        Scanner->>Env: fingerprint(first usable probe)
        Env-->>Scanner: cdn, waf, sapi + rationale
        Scanner->>Verdict: assess(version, attack_surface)
        Verdict-->>Scanner: patched | vulnerable | eol | unknown
        Scanner->>Risk: assess(verdict, env)
        Risk-->>Scanner: score + grade
        Scanner->>Hackability: assess(verdict, env)
        Hackability-->>Scanner: signed signals, positivity ratio, rating
        Scanner->>Remediation: for(verdict, env)
        Remediation-->>Scanner: ordered next steps
        Scanner->>Enrich: verdict + env
        Enrich-->>Scanner: chain, detections, notes, toolchain
        Scanner-->>CLI: ScanResult (+ trace if verbose)
    end
    CLI->>Report: render results (text or JSON)
    Report->>Layout: terminal width, wrap / truncate
    Report-->>Operator: report
    CLI-->>Operator: exit code 0 / 1 / 2
```

## Verdict state machine

How a target moves from raw input to one of the four verdicts. The branch
order is the policy: no version short-circuits to `unknown`, a branch missing
from `FIXED_RELEASES` is `eol` before any version comparison happens, and
only branches that *do* have a published fix ever compare against their floor.

```mermaid
stateDiagram-v2
    [*] --> Normalising
    Normalising --> Probing : valid http(s) URL
    Normalising --> Rejected : not an http(s) URL
    Rejected --> [*]

    Probing --> Evidence : any usable response
    Probing --> NoEvidence : every probe failed

    state Evidence {
        [*] --> ExtractVersion
        ExtractVersion --> ExtractSurface
        ExtractSurface --> [*]
    }

    state Classification {
        [*] --> Assessing
        Assessing --> Unknown : no version fingerprint
        Assessing --> EOL : branch has no fix floor (5.x / 7.x / 8.1)
        Assessing --> Vulnerable : version below branch fix floor
        Assessing --> Patched : version at or above branch fix floor
    }

    Evidence --> Classification : version + surface flags
    NoEvidence --> Classification : surface flags only, version nil
    Classification --> [*] : verdict assigned (exposed for vulnerable / eol)
```

## Rendering flow

A `ScanResult` is produced once and rendered from; display flags affect only
the text renderer. JSON always carries all eleven sections — presentation
decisions never remove data from the machine-readable format — which is why
the two branches below differ in what they pass along but not in what was
collected.

```mermaid
flowchart TD
    R[ScanResult per target] --> J{"--json?"}

    J -->|no| T["Report::Text"]
    T --> TB["summary table<br/>(stacked when narrow)"]
    TB --> T1["summary: verdict, score, reason,<br/>surface, environment"]
    T1 --> T2[ATT&amp;CK kill chain]
    T2 --> T3[detection opportunities]
    T3 --> T4{"--redteam?"}
    T4 -->|yes| T5[attacker-perspective notes]
    T4 -->|no| T6
    T5 --> T6{"--toolchain?"}
    T6 -->|yes| T7[catalogue grouped by phase]
    T6 -->|no| T8
    T7 --> T8{"--verbose?"}
    T8 -->|yes| T9[request trace]
    T8 -->|no| T10
    T9 --> T10["technical summary: hackability,<br/>positivity ratio, signed signals,<br/>prerequisites, reliability, impact"]
    T10 --> REM["remediation: ordered next steps<br/>for this verdict"]
    REM --> RS["run summary: targets, hackable /<br/>inconclusive / not hackable,<br/>positivity ratio"]
    RS --> X[exit code]

    J -->|yes| M["Report.json<br/>all eleven sections, always"]
    M --> X

    X --> E0[0 = nothing exposed]
    X --> E1[1 = usage error]
    X --> E2[2 = vulnerable or eol found]
```
