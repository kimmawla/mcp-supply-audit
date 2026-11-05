# Registry-entry rules (input: a registry entry plus the package metadata it points to)

Facts these rules rely on are in docs/api-notes.md (observed 2026-11-02). Package verification
rules come from the registry's own docs: `docs/modelcontextprotocol-io/package-types.mdx` in
`modelcontextprotocol/registry` at commit `01e5c936ad3048d16562be503d879e523e36d267`.

| Rule | Detects | Severity | Confidence |
|---|---|---|---|
| RG001 | Entry's repository URL does not match the repository declared by the package itself (project URLs / repository field) | high | medium |
| RG002 | Entry's owner in `io.github.<owner>/...` does not match the owner in the entry's repository URL | high | high |
| RG003 | Package named in the entry does not exist in its index | high | high |
| RG004 | Version named in the entry does not exist in the package index | medium | high |
| RG004 | Version exists but has no files | info | high |
| RG005 | Package lacks the ownership marker the registry requires, or the marker names a different server | medium | high |
| RG006 | Entry status is `deleted`: title "removed from the registry" | high | medium |
| RG006 | Entry status is `deprecated` | low | high |
| RG007 | Package publisher or ownership changed shortly before the entry was published: **deferred (not implemented in v0.1)** | - | - |
| RG008 | Entry lists several packages whose identifiers or registry types disagree with each other | low | medium |
| RG009 | Remote URL scheme is not a literal `https` | high | high |
| RG010 | Remote URL host is not the entry's domain namespace or a subdomain of it | info | low |
| RG011 | Remote URL embeds credentials or uses an unusual port | see rule | see rule |

Each rule: a pure function over already-fetched data (no network calls inside rules).
Rules that need data a source did not provide are recorded in `coverage` as skipped, with a reason
from the fixed set in docs/finding-spec.md. All text from the entry or a package (names, URLs,
descriptions, status messages) is untrusted and appears only as evidence under `untrusted_text`.

## Data and skipped-by-design cases

"Skipped by design" means the data lives only on a host outside the allowlist, so the check never
runs for that case. It is recorded every time, never treated as a pass.

| Rule | Data used (allowed hosts only) | Skipped by design | Other skips |
|---|---|---|---|
| RG001 | PyPI release JSON `info.project_urls`; npm version doc `repository.url` | `oci`, `mcpb`, `nuget`, `cargo` (`unsupported_package_type`) | `remote_only`; no `repository` in the entry, no repository URL in the package, or a URL that does not normalize (`not_determinable`) |
| RG002 | Entry `name`, `repository.url` | none | domain namespaces (`not_applicable`); no `repository` or a non-GitHub repository host (`not_determinable`). Runs for remote-only entries too |
| RG003 | npm version doc 404 body; PyPI project JSON status code | `oci`, `mcpb`, `nuget`, `cargo` | `remote_only` |
| RG004 | npm version doc 404 body; PyPI release JSON (status and `urls`) | `oci`, `mcpb` (no `version` field; the version is in the identifier), `nuget`, `cargo` | `remote_only` |
| RG005 | PyPI release JSON `info.description`; npm version doc `mcpName`; entry `fileSha256`, `registryBaseUrl` and `identifier` for `mcpb` | `oci`, `nuget`, `cargo`; for `mcpb`, the hash and the registry's HEAD reachability check | `remote_only` |
| RG006 | Entry `_meta["io.modelcontextprotocol.registry/official"]`, or `_meta` directly (the documented shape) | none | neither shape (`shape_mismatch`). Runs for remote-only entries too |
| RG007 | deferred | | |
| RG008 | Entry `packages[]` | none | `remote_only` |
| RG009-RG011 | Entry `remotes[].url`, `remotes[].variables` | none | entries without `remotes` do not run these; see each rule |

When audit_server is given a package name (with its ecosystem) instead of a registry name, every
RG rule is skipped with `not_determinable`, detail `registry entry not provided`
(docs/tool-surface.md).

## RG001: declared repository URLs are consistent
Compare `normalize_repo_url(entry repository.url)` with the normalized package-declared URL:
npm version doc `repository.url`; for PyPI, every value in `info.project_urls` (labels are
free-form, e.g. `Repository`, `Source`, `Code`). A match with any one passes. No match is the
finding; evidence is the entry URL.

`normalize_repo_url` (src/mcp_supply_audit/detectors/registry.py) strips a leading `git+`, any
trailing `/` and `.git`, lowercases the host, and drops a leading `www.`. Scheme, userinfo, port,
path case, query and fragment are kept. A string without a scheme and host (npm shorthand
`github:owner/repo`, scp-like `git@github.com:owner/repo.git`) returns None, and the check is
`not_determinable`. `repository.subfolder` (monorepos) is ignored: the comparison is on the
repository, not the folder.

## RG002: owner match
Applies to `io.github.<owner>/<name>` entries whose `repository.url` host is `github.com`. Compare
`<owner>` with the first path segment of the repository URL, case-insensitively (the registry
keeps owner case, e.g. `io.github.Zqvex-Owner/...`; GitHub logins are case-insensitive).

## RG003 and RG004: package and version exist
- npm: `GET /{pkg}/{version}`. 200 means both exist. A 404 body `"Not Found"` is RG003 (no such
  package); `"version not found: <v>"` is RG004 (no such version). Any other 404 body is
  `shape_mismatch`. Ranges are not resolved by npm and count as missing versions.
- PyPI: `GET /pypi/{p}/{v}/json`. 200 means both exist. On 404, `GET /pypi/{p}/json` and use only
  the status code: 404 is RG003, 200 is RG004. The body is not read, so a large project (botocore,
  3.87 MB) does not hit the size cap.
- RG004, zero files: PyPI release JSON 200 with `"urls": []` (e.g. requests `0.0.1`) is an info
  finding: the version is listed, but there is nothing to install or verify. npm versions always
  carry `dist`, so this case is PyPI-only.

## RG005: ownership marker (matches the registry's verifier code)
Findings say the package does not match the registry's published ownership check and name the
verifier commit (`01e5c936`). They never say the registry accepted or rejected anything: whether
the check ran at publish time is not visible (`EnableRegistryValidation`).

RG005 does what the registry's verifier code does, not only what package-types.mdx says. The code
is in `modelcontextprotocol/registry` at `01e5c936`, `internal/validators/registries/`; the
details and the points where code and docs differ are in docs/api-notes.md, "Ownership
verification code".

- **PyPI** (`pypi.go` `validatePyPIPackage`, `mcpname.go` `containsMCPNameToken`): read
  `info.description` from `GET /pypi/{id}/{version}/json` for the version the entry lists. Pass if
  the exact text `mcp-name: <entry name>` (one space, case-sensitive) occurs followed by a
  boundary: end of text, any character outside `[A-Za-z0-9._/-]`, or `-->` / `--!>`. Every
  occurrence is tried. No marker, or only markers naming other servers, is a finding; evidence is
  the description from the first `mcp-name:`.
- **npm** (`npm.go` `validateNPMPackage`): read `mcpName` from `GET /{pkg}/{version}`. A missing or
  empty `mcpName` is "has no mcpName"; any other value must equal the entry name exactly
  (case-sensitive). The value found is the evidence.
- **mcpb** (`mcpb.go` `ValidateMCPB`, `validateMCPBUrl`), every check made before the registry's
  HEAD request: `fileSha256` non-empty (its format is not checked on publish); no
  `registryBaseUrl`; the identifier parses as a URL with no control characters; host is
  `github.com`, `www.github.com`, `gitlab.com` or `www.gitlab.com` (port included, so
  `github.com:443` fails); the decoded path is a GitHub release asset
  (`/owner/repo/releases/download/tag/file`) or a GitLab release or package-file URL; scheme
  `https`; and the identifier contains `mcp` in any letter case. Each failed check is a finding.
  The HEAD reachability check and the hash itself need github.com or gitlab.com: skipped
  (`unsupported_package_type`).
- **oci, nuget, cargo**: the markers (image config label, README on NuGet or crates.io) are only on
  hosts outside the allowlist: skipped (`unsupported_package_type`).

## RG006: status
- Fetch with `include_deleted=true`; without it a deleted entry is a 404 (api-notes).
- `deleted`: title "removed from the registry". High severity, medium confidence. The finding
  states only that the entry was removed and quotes the status message. The registry also uses
  `deleted` for renames and consolidations, and the API does not say who set it, so the finding
  does not say why it was removed.
- `deprecated`: low severity, high confidence. The entry is still listed in default searches;
  observed messages point to a replacement. The finding says the publisher or registry marked it
  deprecated and quotes the message.
- `active`: no finding.
- Evidence: `statusMessage`, quoted under `untrusted_text`. It is free text set through the API
  and may contain anything. If absent, evidence is empty and the title says there was no message.

Remote-only entries (`remotes` and no `packages`) run RG002 and RG006 as well as RG009-RG011:
both check the entry, not a package. Package rules and RG008 are skipped with `remote_only`.

## RG007: deferred (not implemented in v0.1)
Reason: neither source gives an ownership history. PyPI `ownership` lists current roles only, with
no dates. npm `maintainers` is current only; per-version `_npmUser` and `time` exist only in the
full packument (up to 11.2 MB, over the npm response cap). A switch to trusted publishing would
also look like a new publisher. Revisit if a source with dated ownership changes is allowed.

## RG009-RG011: remote URLs (static only; never fetched)
Evidence for RG009, RG010 and RG011 is only the scheme, host and port (`url_evidence`), plus, for
RG011, the names of the flagged parameters. The path, query values, userinfo and fragment are never
shown. A static test checks that these rules pass nothing else as evidence.

Elsewhere (RG001, RG002, the mcpb identifier in RG005), a URL is shown through `display_url`:
userinfo, the fragment, and the values of every parameter in the flag list
(`data/rg011_credential_params.yaml`) and the broader redact list
(`data/url_redact_params.yaml`) become `<redacted>`. The redact list only hides values; it never
raises a finding. On top of that, every finding's evidence passes through `secrets.scrub`, which
replaces any span matching a documented credential format with `<redacted>`.

- **RG009, https only**: the scheme must be the literal `https`. Any other scheme (`http`, `ws`,
  ...) is high severity, high confidence. A scheme given by a placeholder is reported the same way,
  since https is not guaranteed.
- **RG010, host within the namespace domain**: domain namespaces only. Reverse all labels of the
  namespace to get a domain (`ai.zqvex` -> `zqvex.ai`, `com.example.api` -> `api.example.com`).
  The host must equal that domain or be a subdomain of it; otherwise an info finding with low
  confidence. `not_applicable` for `io.github.*` names (only 77 of 672 sampled hosts related to
  the owner) and for hosts given by a placeholder. In the samples, 1,050 of 1,079 URLs matched.
- **RG011, credentials and ports**:
  - userinfo in the URL (`user:pass@` or `user@`): high severity, high confidence.
  - a query parameter whose name is in the credential list (data file) with a literal value:
    high severity, medium confidence.
  - the same parameter with a `{placeholder}` value: low severity, medium confidence. The secret is
    supplied at install time but travels in the URL, where proxies and logs keep it. One such case
    was seen in the sample.
  - a query value or path segment that matches a documented credential format (secrets.py:
    GitHub, GitLab, Slack, Stripe secret/restricted keys, AWS access key ids): high severity,
    medium confidence. The finding names the parameter or the path segment index, never the value.
    A parameter already flagged by name is not flagged again by shape.
  - an explicit literal port other than 443: low severity, medium confidence. A port given by a
    placeholder: `not_applicable`, as for RG010 placeholder hosts.

## OWASP MCP Top 10 mapping
Ids are the exact ones in src/mcp_supply_audit/owasp.py; `RULE_OWASP` in
detectors/registry_rules.py must match this table (tests compare them).

| Rule | OWASP id | Rationale |
|---|---|---|
| RG001 | MCP04:2025 | The listing points at different source than the package declares, so what is installed may not be what was reviewed. |
| RG002 | MCP04:2025 | A namespace owner who is not the repository owner suggests a listing that borrows another project's code. |
| RG003 | MCP04:2025 | A listed package that does not exist can be registered by anyone, who then receives every install. |
| RG004 | MCP04:2025 | A missing or file-less version means the installed artifact differs from the one the listing names. |
| RG005 | MCP04:2025 | Without the ownership marker the package is not proven to belong to the server it is listed under. |
| RG006 | MCP04:2025 | A removed or deprecated entry is an artifact the registry no longer lists as current. |
| RG008 | MCP04:2025 | Conflicting packages leave it unclear which artifact is the server. |
| RG009 | MCP01:2025 | A non-https remote sends tokens and tool traffic where they can be read in transit. |
| RG010 | MCP04:2025 | A remote outside the namespace domain may be operated by someone other than the verified publisher. |
| RG011 credentials | MCP01:2025 | Credentials in a URL leak through logs, proxies, and anyone who sees the listing. |
| RG011 port | MCP04:2025 | An unusual port is a weak sign the endpoint is not the publisher's standard service. |
