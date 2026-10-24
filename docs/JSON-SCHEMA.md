# JSON schema (v3.0)

The JSON report is a stable envelope. The schema version is separate from the
gem version: adding fields is backward-compatible; removing or renaming one
requires a schema bump.

```json
{
  "schema_version": "3.0",
  "tool": {
    "name": "php2shell-poc2026",
    "version": "3.0.0",
    "homepage": "https://github.com/ctkqiang/PHP2ShellPOC2026"
  },
  "generated_at": "2026-10-24T00:00:00Z",
  "options": {},
  "summary": {},
  "results": {
    "https://example.com/": {}
  }
}
```

## Top-level fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `"3.0"` |
| `tool` | object | `name`, `version`, `homepage` |
| `generated_at` | string | RFC 3339 / ISO 8601 UTC |
| `options` | object | Effective options; secrets redacted |
| `summary` | object | Counts and coverage, identical to other formats |
| `results` | object | Map keyed by target display URL |

## `summary`

```json
{
  "total": 1,
  "exposed": 0,
  "vulnerable": 0,
  "eol": 0,
  "patched": 0,
  "no_php": 0,
  "unverified": 1,
  "hackable": 0,
  "not_hackable": 0,
  "decision_unknown": 1,
  "unknown": 0,
  "inconclusive": 1,
  "errors": 0,
  "assessable": 0,
  "blocked": 1,
  "auth_wall": 0,
  "rate_limited": 0,
  "soft_404": 0,
  "unreachable": 0,
  "coverage": { "attempted": 3, "usable": 0, "percent": 0.0 },
  "requests": 3,
  "duration_ms": 1234.5,
  "scope_skipped": 0,
  "generated_at": "2026-10-24T00:00:00Z",
  "tool": { "name": "php2shell-poc2026", "version": "3.0.0" },
  "profile": "deep",
  "format": "json"
}
```

`exposed = vulnerable + eol`. `unverified = unknown + inconclusive`.
`assessable = exposed + patched + no_php`. Coverage is probe-level, not
target-level; `usable` counts `2xx/3xx` responses.

`hackable`, `not_hackable` and `decision_unknown` count the per-target
`hackability.answer` values (`yes`, `no`, `unknown`). They normally mirror
`exposed`, `patched + no_php` and `unverified`, but they are the fields the
human report uses for its bottom line so the summary cannot disagree with
the per-target decision cards.

## Per-target object

| Field | Type | Notes |
|---|---|---|
| `target` | object | `target`, `display`, `url`, `scheme`, `host`, `ascii_host`, `port`, `international`, `ip` |
| `verdict` | object | See below |
| `environment` | object | `server`, `via`, `edge`, `cdn`, `waf`, `hosting`, `sapi`, `sapi_rationale`, `frameworks`, `framework_versions`, `tls`, `dns`, `block_page`, `access` |
| `risk` | object | `score` (number or null), `grade`, `scale`, `friction` |
| `attack` | object | `assessment_path[]`, `kill_chain[]` |
| `detections` | array | `layer`, `control`, `detail` |
| `red_team` | array of strings | Attacker-perspective notes |
| `tooling` | array | `phase`, `tool`, `purpose`, `relevance`, `techniques`, `url`, `priority`, `offensive` |
| `fingerprint` | object | Headers, cookies, statuses, paths, frameworks, PHP markers, control, coverage, TLS, DNS, discovery |
| `hackability` | object | `rating`, `label`, `ratio` (number or null), `answer` (`yes`/`no`/`unknown`), `action`, `hackable` (boolean or null), counts, signals, prerequisites, reliability, impact, friction |
| `remediation` | array of strings | What to do next |
| `next_actions` | array | `label`, `command`, `why`, `authorized` |
| `probes` | array | Evidence records; `body_excerpt` only with `--evidence` |
| `trace` | array of strings | Only populated with `-v` |
| `meta` | object | Tool version, timestamps, duration, request count, profile, scope |
| `error` | string or null | Per-target internal error, if any |

### `verdict`

```json
{
  "status": "inconclusive",
  "label": "INCONCLUSIVE",
  "reason_code": "blocked",
  "reason": "every probe, including a random control path, returned HTTP 403 …",
  "version": null,
  "version_source": null,
  "version_precision": null,
  "confidence": "low",
  "branch": null,
  "fix_floor": null,
  "attack_surface": {
    "php_detected": false,
    "upload_progress": false,
    "phpinfo_exposed": false,
    "php_errors": false,
    "php_paths_live": false,
    "framework": null,
    "auth_wall": false,
    "php_versioned": false
  },
  "access": {
    "state": "blocked",
    "label": "edge denied every probe",
    "reason": "…",
    "control": { "path": "/php2shell-…txt", "status": 403, "similarity": 1.0 },
    "details": { "probes": 3, "main": 1, "controls": 2, "statuses": [403] }
  },
  "exposed": false,
  "assessable": false
}
```

Statuses: `vulnerable`, `eol`, `patched`, `unknown`, `no_php`, `inconclusive`.
Reason codes include: `vulnerable`, `eol`, `patched`, `no_version`,
`branch_only`, `newer_than_table`, `no_php`, `blocked`, `restricted`,
`auth_wall`, `rate_limited`, `soft_404`, `unreachable`, `server_error`,
`internal_error`.

### `risk`

```json
{
  "score": null,
  "grade": "UNKNOWN",
  "scale": "exposure severity (CVSS-shaped, not a CVSS vector)",
  "friction": {
    "score": 9,
    "level": "high",
    "factors": [
      { "factor": "waf", "weight": 3, "note": "… may block crafted requests" }
    ]
  }
}
```

A null `score` is not zero. It means the evidence was insufficient to assign
exposure severity.

### `environment.block_page`

`null` when the response was not a block page. Otherwise:

```json
{
  "vendor": "OVHcloud",
  "summary": "Request blocked due to suspicious activity",
  "title": "Your request has been blocked - OVHcloud",
  "ua_sensitive": true,
  "status": 403
}
```

`vendor` is `null` for a generic edge denial that matches no known product.
`ua_sensitive` is a hint that the scanner's identifying User-Agent may be the
trigger, not proof that a different User-Agent will be allowed.

### `probes[]`

| Field | Notes |
|---|---|
| `method`, `purpose`, `url`, `request_uri` | What was requested |
| `status`, `status_class`, `elapsed_ms`, `bytes`, `body_sha256` | What came back |
| `truncated`, `http_version`, `title`, `server`, `x_powered_by`, `content_type` | Response metadata |
| `set_cookie_names`, `redirects`, `error`, `error_kind`, `tls` | Transport/evidence |
| `php_markers` | `kind`, `evidence`, `confidence` |
| `body_excerpt` | Only with `--evidence`; target-controlled data |

## NDJSON

`--format ndjson` emits one JSON object per line:

```json
{"record_type":"target","generated_at":"…","result":{…}}
{"record_type":"run","generated_at":"…","summary":{…}}
```

## Stability notes

- `results` is keyed by display URL. Targets are deduplicated by normalised
  URI before scanning.
- `body_excerpt` is omitted by default; it can contain secrets or hostile
  content.
- `trace` is empty unless `-v`.
- `--compact` changes whitespace only.
