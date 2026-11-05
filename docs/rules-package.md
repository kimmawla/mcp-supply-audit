# Package rules (source of truth)

Tool: `audit_package(name, ecosystem, version="")`, ecosystem `pypi` or `npm`. Findings are indicators,
never verdicts. All data comes from the four allowed hosts. Nothing is downloaded or executed.

Every rule below was checked against docs/api-notes.md ("audit_package data", measured 2026-11-04) and
the "audit_package data" section of docs/tool-surface.md. Where the data a rule needs is not available
from an allowed host within the response caps, the rule is a skipped check with a fixed detail, not a
guess. Implementation: detectors/package_rules.py (rules) and package_audit.py (fetching, coverage).

## Version resolution
- If `version` is given: validate it and use it. For npm a dist-tag (`latest`, `next`) is accepted the
  same way, because `/{pkg}/{tag}` returns that version's document.
- If empty, resolve the latest version with the cheapest bounded endpoint (api-notes, "Resolving the
  latest version"):
  - npm: `GET /{pkg}/latest`. One request; the body is the version document, so no second fetch.
  - PyPI: `GET /pypi/{p}/json` for `info.version`, then `GET /pypi/{p}/{v}/json`. There is no
    per-version alternative, and the project JSON exceeds the 512 KiB cap for large projects (django
    630,589 B). Then, or on any other failure, return a `ToolError` whose fixed message depends on
    the typed cause:
    - `ResponseTooLarge`: the project document (PyPI) or latest version document (npm) exceeds the
      size cap, so pass a version. No retry advice: a retry cannot shrink it.
    - `SourceUnreachable` or `SourceTimeout`: the index could not be reached; retry, or pass a version.
    - `ShapeMismatch` (including a resolved version that fails the checks below): the response was
      not in the expected form; pass a version.
    The error carries the cause's skip reason and detail `latest version could not be resolved`,
    which audit_server records as a skipped check.
- There is no "OSV-only" fallback: PK001 queries OSV for one exact version, so without a version no rule
  can run and the `ToolError` above is the only outcome.
- A resolved version must pass `validate_version` unchanged, or resolution has failed. For npm it must
  also be an exact semver: a document whose own `version` is a tag (`next`) or anything else has not
  resolved one. Such a version is a `shape_mismatch`, and the tool raises a short `ToolError` that does
  not repeat the value: the `ShapeMismatch` one above when no version was given, else one saying the
  index returned a malformed version. No report is built and OSV is not queried.
- The audited version is the version document's own `version` (npm, so a tag resolves) or the version
  the release JSON was fetched for (PyPI). The report always names it under `audited`
  (docs/finding-spec.md). PK001 queries OSV with that same version, never a tag. The name under
  `audited` is the caller's name after validation, never a name from a response.
- A package or version the index does not have is a `ToolError`: OSV answers `{}` for unknown packages
  too (api-notes), so a report would read as "no findings" for something that does not exist.

## Rules

| Rule | Detects | Severity | Confidence |
|---|---|---|---|
| PK001 | OSV advisories affecting this exact version | from the highest advisory severity label; medium if none given | high |
| PK002 | Version is yanked (PyPI) or deprecated (npm) | medium | high |
| PK003 | npm install-time scripts present (`preinstall`, `install`, `postinstall`) | medium | high for presence; not a verdict |
| PK004 | No provenance attestation for this version | info | medium |
| PK005 | Version published within the last 7 days | info | low |
| PK006 | No repository URL declared in package metadata | low | medium |

Rule notes:
- PK001 uses `clients/osv.query_vulns` (the narrow POST) with a 2-page cap, for both ecosystems (the PyPI
  release JSON's `vulnerabilities` list is not used). The label is each record's
  `database_specific.severity`, mapped `CRITICAL` -> critical, `HIGH` -> high, `MODERATE` -> medium,
  `LOW` -> low; any other value counts as no label. GHSA records carry it and PYSEC records do not
  (api-notes, "OSV severity labels"), so a PyPI result with only PYSEC records is medium. CVSS vectors are
  not scored. The title carries the count ("at least N" when the 2-page cap or a pagination stop truncated
  the result) and the highest label, both written by code; evidence is up to 5 advisory ids. The count
  and label are not in the evidence because 5 GHSA ids already fill most of the 120-character cap. Never
  advisory summary or details text.
- PK001 evidence ids pass `advisory_id`: a str, ASCII, at most 64 characters, a prefix from
  `data/pk001_advisory_id_prefixes.yaml` (`GHSA-`, `PYSEC-`; api-notes, "OSV advisory ids"), then
  `[A-Za-z0-9._-]` only. Every record counts toward the title, whatever its id. When ids were left out,
  the evidence starts with `N id omitted` / `N ids omitted` (N written by code), then the passing ids; if
  none passes, that phrase is the whole evidence and the finding stands. `parse_page` already refuses a
  page holding a record without a str id (the whole OSV result is then `shape_mismatch`), so in practice
  only string ids that fail the pattern are omitted; the rule handles missing ids regardless.
- PK002 reads PyPI `info.yanked` and `info.yanked_reason` from the release JSON (both describe that
  version) and npm's `deprecated` string. A non-empty `deprecated` is a deprecation; an empty string is
  treated as not deprecated (not observed). Evidence: the fixed phrase `yanked` or `deprecated`, then the
  reason or message, which is target text and goes through `evidence_snippet`, capped and escaped.
- PK003 evidence: the script NAMES only, never the command text. The client keeps only the names, so the
  commands never reach a rule. PyPI install-time code needs file downloads from a host that is not
  allowed, so for PyPI this rule is skipped with `not_determinable` (a field no allowed source provides),
  detail "PyPI install-time code needs file download".
- PK004, npm: no `dist.attestations.provenance.predicateType` in the version document is a finding. No
  extra request. PyPI: `GET /integrity/{p}/{v}/{filename}/provenance` for files from the release JSON's
  `urls[]` (the Simple API is project-level and not needed), at most 4 files per version, concurrently. Any
  checked file with provenance passes. If every file was checked and none has provenance, that is a
  finding, with location `PyPI /integrity provenance, N of M files checked` (both counts written by
  code; the npm location stays `npm dist.attestations`). If the version has more than 4 files and none of the 4 checked has provenance, skip with
  `not_determinable`, detail "too many files to check". A version with no files is `not_applicable`,
  detail "version has no files". A failed provenance request, when no other file had provenance, is a
  skip with that request's reason.
- PK005 is PyPI only: the earliest `upload_time_iso_8601` among this version's files, compared with the
  time of the audit. A version with no files is `not_determinable`, detail "version has no files". npm has
  no time in the per-version document, so skip with `not_determinable`, detail "npm version document has
  no publish time". Evidence: the earliest upload time.
- PK006 reads every PyPI `project_urls` value plus `info.home_page`, and the npm `repository` field
  (object `url` or plain string). PyPI labels are free-form (api-notes), so any non-empty value counts as
  declared and the rule fires only when there is none; a documentation-only URL passes. Evidence is empty.
- A report for a package with no findings is not evidence it is safe. The standing note stays.

## OWASP MCP Top 10 mapping
Ids are the exact ones in src/mcp_supply_audit/owasp.py; `RULE_OWASP` in detectors/package_rules.py must
match this table (tests compare them).

| Rule | OWASP id | Rationale |
|---|---|---|
| PK001 | MCP04:2025 | A dependency with known advisories is a published weakness in what gets installed. |
| PK002 | MCP04:2025 | A yanked or deprecated version is one its publisher has withdrawn from normal use. |
| PK003 | MCP04:2025 | Install-time scripts run publisher code on the installing machine before anyone reviews it. |
| PK004 | MCP04:2025 | Without provenance nothing ties the artifact to a source repository and build. |
| PK005 | MCP04:2025 | A very new version has had little time for anyone to notice tampering. |
| PK006 | MCP04:2025 | Without a declared repository the package cannot be compared with any source. |

## Coverage
- Each rule is one check, `PK001` to `PK006`, listed as ran or skipped with a reason (and a detail where
  the table in docs/finding-spec.md defines one).
- Metadata (release JSON or version document) is fetched first, because it decides the audited version
  and whether the package exists. Then OSV and the PyPI provenance requests run concurrently.
- If the metadata fetch fails, PK002-PK006 are skipped with its reason and PK001 still runs for the
  caller's version. Exception: an npm version that is not an exact semver (a dist-tag) could not be
  resolved, so PK001 is skipped with the metadata reason too (OSV would answer `{}` for a tag). If OSV
  fails, PK001 is skipped with its reason. PK003 for PyPI is always the fixed skip above.
- If both the metadata and OSV failed, the tool raises `ToolError` (nothing could run).
- A rule that raises is skipped with `rule_error`; details go to stderr only.

## Deliberately not implemented in v0.1
- Maintainer or owner change detection (no history in either API; same reason as RG007).
- Package popularity or download counts (no allowed host provides them).
- Typosquat comparison (done by `check_typosquat`, combined by `audit_server`).
- Scanning package contents (no file downloads).

## Behavior
- Package name validated by `validation.py`. Names and versions are percent-encoded one path segment each.
- Clients raise only typed errors, and each rule turns them into skipped checks with the eight fixed reasons.
- Rules are pure functions over already-fetched, normalized data. No network calls inside rules.
- `ToolError` only for invalid input, a package or version the index does not have, an unresolvable
  latest version, a malformed resolved version, or when nothing can run.
- Coverage lists every rule as ran, or skipped with a reason and a detail.
- All target text is untrusted: `safe_json` parsing, `evidence_snippet` for any quoted text.

## Known limits
What PyPI and npm cannot tell us from the allowed hosts. Each limit shows up in coverage as a skipped
check, or is a reason a check passes that the reader should not over-read.

| Limit | Why | Effect |
|---|---|---|
| Named version only | audit_package reads the metadata and OSV advisories of the one version it audits; it does not resolve or audit that version's dependencies | A vulnerable, yanked or deprecated dependency is not reported |
| Latest version of a large PyPI project | Only the project JSON names it, and it exceeds the 512 KiB cap (django, numpy, boto3) | The caller must pass a version |
| PyPI install-time code | Build hooks live in the sdist, a file download from files.pythonhosted.org (not allowed) | PK003 never runs for PyPI |
| npm install behaviour not in `scripts` | Only `preinstall`, `install` and `postinstall` in the version document are read | Install-time work npm triggers on its own is not detected |
| npm publish time | Only the full packument has `time`; it reaches 11.2 MB | PK005 never runs for npm |
| PyPI provenance on many-file versions | One request per file; at most 4 are checked | PK004 is skipped when none of the first 4 files has provenance |
| OSV ids with an unlisted prefix | Only prefixes seen as record ids are allowed in evidence | The record counts, but its id is shown only as part of "N ids omitted" |
| What provenance proves | Provenance is checked for presence only; the attestation is not verified and its repository is not compared with PK006's | A present attestation is not proof the build is honest |
| Severity of PYSEC advisories | PYSEC records carry no label and CVSS vectors are not scored | A PyPI finding from PYSEC records only is reported as medium |
| Withdrawn advisories | None seen in samples, so they are not filtered | A withdrawn advisory would still count in PK001 |
| More than two OSV pages | PK001 stops at 2 pages | The count says "at least N" |
| "No advisories" vs "unknown to OSV" | OSV answers `{}` for both | PK001 passing means OSV listed nothing, not that OSV knows the package |
| Repository URL meaning | PyPI labels are free-form | PK006 passes on any project URL, even a documentation link |
| Owner history, downloads, package age | Not in any allowed per-version source (tool-surface.md) | Not reported; see "Deliberately not implemented" |

PyPI provenance is checked only for versions with at most 4 files (MAX_PROVENANCE_FILES); larger versions get a skip.
