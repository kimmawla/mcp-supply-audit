# Finding and report spec (source of truth)

## Finding
- rule_id: e.g. TD001 (tool definitions), RG001 (registry), PK001 (package), CF001 (config)
- title, severity: critical | high | medium | low | info
- confidence: high | medium | low  (how sure the rule is, separate from severity)
- owasp: list of OWASP MCP Top 10 ids (use the exact ids from the OWASP page, not memory)
- location: tool name / field / character offset, or file and line
- evidence: sanitized snippet, max 120 chars, returned under `untrusted_text`
- remediation: one sentence

## Report
- findings (sorted by severity, then confidence)
- summary: counts by severity
- coverage: checks that ran, and checks skipped with the reason (like missing_sources in vuln-triage)
- assessment: "findings_present" or "no_findings_detected"
- data_sources (optional, omitted when empty): dated data files a check compared against, each
  `{name, as_of, entry_count}` plus `partial` (bool) when the file records it (e.g. check_typosquat's
  reference names: `entry_count` counts curated entries plus listed names in the compact format of
  docs/rules-typosquat.md, and `partial` is true when the registry crawl stopped at its page cap)
- notes (optional, omitted when empty): info notes in fixed wording plus a date or count only,
  never target text. Notes never change the assessment. check_typosquat's fixed set, including
  the partial-list note, is in docs/rules-typosquat.md ("Notes (fixed set)").
- audited (optional, omitted when absent): the package a package audit checked, as
  `{ecosystem, name, version}`. `version` is the one audited: the caller's, or the latest version
  the tool resolved (docs/rules-package.md, "Version resolution"). Both strings passed
  validation.py, so they hold only the characters its name and version patterns allow.
- audited_by_report (optional, omitted when empty): on a merged report (audit_server), each
  package sub-report's `audited`, keyed by sub-report name, e.g.
  `{"audit_package:packages[0]": {ecosystem, name, version}}`.
- note (always present): absence of findings is not proof of safety; static checks only

## Merged reports (audit_server)
`merge_reports` in findings.py combines named sub-reports into one Report:
- findings from every sub-report, re-sorted; each `location` is prefixed `<sub-report>/`.
- coverage `ran` and `skipped` entries prefixed `<sub-report>/`, plus one skipped check, named
  after the sub-report, for each sub-check that produced no report (failed, or still running at
  the deadline).
- data_sources and notes concatenated without duplicates; `audited` kept per sub-report under
  `audited_by_report`; the assessment recomputed; the standing note present once.
## Coverage reasons (fixed set)
A skipped check is `{check, reason}`, plus an optional `detail` from the fixed set in "Skip
details" below. `reason` is exactly one of the eight strings below: never
free text, never text taken from a target, never an exception message. `build_report` rejects any
other string. Each reason has a fixed coverage text that the report shows with it (`text` in the
serialized coverage), so the limit is stated in plain words. The table and `SKIP_REASON_TEXT` in
findings.py must match word for word (a test compares them).

| reason | Used when | Coverage text |
|---|---|---|
| `unsupported_package_type` | The entry's package type is not `pypi` or `npm` (`oci`, `mcpb`, `nuget`, `cargo`); verifying it needs a host outside the allowlist | Package type not supported: its registry is outside the allowed hosts, so this check did not run. |
| `remote_only` | The entry has `remotes` and no `packages`, so package checks do not apply | Remote-only server: package checks do not apply. The remote URL was checked as text and never contacted. |
| `response_too_large` | A source response exceeded its size cap (docs/tool-surface.md) | A source response exceeded the size cap, so this check did not run. |
| `source_unreachable` | Timeout, connection error, or an HTTP error after the retry policy in CLAUDE.md | A data source could not be reached, so this check did not run. |
| `shape_mismatch` | A response, input, or rule data file lacked the expected fields or had them with other types (includes a tools/list entry that is not a JSON object, and a malformed rule data file) | Data was not in the expected shape, so this check did not run. |
| `not_applicable` | The rule's precondition does not hold for this target: e.g. RG002 or RG010 for a namespace they do not cover, RG010/RG011 when the host or port is a `{placeholder}` | This check does not apply to this kind of target, so it did not run. |
| `not_determinable` | The value the rule needs is not available: a field no allowed source provides, a URL that does not normalize, a missing rule data file, or registry checks when only a package was given | The data this check needs cannot be determined from the allowed sources, so it did not run. |
| `rule_error` | The rule raised an unexpected exception (details go to stderr only) | This check failed with an internal error, so its result is unknown. |

## Skip details (fixed set)
A skipped check may add a `detail`, shown as `detail` in the serialized coverage. It is exactly
one of the strings below, defined as `SkipDetail` in findings.py: never free text, never text
taken from a target. The order of this table matches the enum (a test compares them).

| detail | Used with | When |
|---|---|---|
| `name too short` | `not_applicable` | check_typosquat: the package part (npm) or name part (registry) is under 5 characters; TS002-TS006 |
| `name has no scope or namespace` | `not_applicable` | check_typosquat: TS006 for a PyPI or unscoped npm name |
| `name is a reference entry` | `not_applicable` | check_typosquat: the name exactly equals a reference name |
| `no reference names for this ecosystem` | `not_determinable` | check_typosquat: the reference file has no entries for the ecosystem |
| `reference file malformed` | `shape_mismatch` | check_typosquat: the reference file is not ASCII, not valid JSON, or not in the expected shape |
| `reference file unreadable` | `not_determinable` | check_typosquat: the reference file is missing or cannot be read |
| `rule not used for registry names` | `not_applicable` | check_typosquat: TS005 on a registry name (registry tuning B) |
| `PyPI install-time code needs file download` | `not_determinable` | audit_package: PK003 for a PyPI package |
| `version has no files` | `not_applicable`, `not_determinable` | audit_package: a PyPI version with `urls: []`; PK004 (`not_applicable`: nothing to attest) and PK005 (`not_determinable`: no upload time) |
| `too many files to check` | `not_determinable` | audit_package: PK004 for a PyPI version with more files than the per-version provenance cap, none of the checked files having provenance |
| `npm version document has no publish time` | `not_determinable` | audit_package: PK005 for an npm package |
| `too many servers` | `shape_mismatch` | scan_mcp_config: every server after the first 200 |
| `server over a size limit` | `shape_mismatch` | scan_mcp_config: a server with more than 100 args or a string over 4096 characters |
| `server entry malformed` | `shape_mismatch` | scan_mcp_config: a server that is not an object, or a field of the wrong type |
| `runner syntax not documented` | `not_determinable` | scan_mcp_config: CF001/CF006 when the runner's docs do not cover an option or version form used (docs/api-notes.md) |
| `value is a placeholder` | `not_determinable` | scan_mcp_config: the value a rule needs is a `${...}` variable, e.g. CF002 on `${BASE_URL}/mcp` |
| `latest version could not be resolved` | `response_too_large`, `source_unreachable`, `shape_mismatch` | audit_server: audit_package was given no version and the latest could not be resolved (the reason is the typed cause) |
| `package or version not found` | `not_determinable` | audit_server: the index has no such package or version |
| `registry entry not provided` | `not_determinable` | audit_server: every RG check when only a package name was given |
| `registry entry not found` | `not_determinable` | audit_server: the registry has no entry with that name; also the package checks that needed it |
| `more packages than audit_server checks` | `not_determinable` | audit_server: pypi/npm packages after the first 3 an entry lists |
| `check did not finish before the deadline` | `source_unreachable` | audit_server: a sub-check still running at the 30 s deadline |
