# External API notes

Observed 2026-11-02 with curl against the live services. Everything below comes from real
responses or from the cited docs; nothing is filled in from memory. Where a claim rests on a
sample rather than the whole dataset, the sample is named. Re-check before relying on a detail
that may have changed.

Fixtures: `tests/fixtures/api/` (index at the end), written as ASCII JSON (any non-ASCII
character is a `\uXXXX` escape). Most are real responses, trimmed only by deleting keys or
array items, never by editing values other than personal ones. The four marked **synthetic** in the index stand in for
third-party MCP server responses: each keeps every field and nesting level of the real
response, takes its values from the `io.github.kimmawla/vuln-triage-mcp` entry where that entry
has the field, and uses invented `zqvex-*` values elsewhere (name, namespace, status message).
The seven marked **pseudonymized** are real responses with every personal value replaced (see
"Personal data in fixtures" after the index). The real captures of both kinds are kept outside
the repository in `local_fixtures/` (gitignored, never tracked);
`tests/test_fixture_parity.py` checks that the shapes match when that folder is present.

Third-party MCP servers and publishers are not named in these notes. Where an observation
came from one, it says what was seen; the sizes, counts and lengths are from the real
responses.

## Allowed hosts

Outbound requests go only to these hosts (see docs/tool-surface.md):

- `registry.modelcontextprotocol.io`
- `pypi.org`
- `registry.npmjs.org`
- `api.osv.dev`

URLs found inside responses (repository URLs, tarball URLs, `websiteUrl`, `remotes[].url`,
`registryBaseUrl`, MCPB release URLs, provenance links on other hosts) are data, never
fetched. OSV.dev is described in its own section below.

## Summary table

| Endpoint | OK | Missing | Rate-limit headers | Typical size | Largest seen |
|---|---|---|---|---|---|
| Registry `GET /v0/servers` | 200 | 200 with `servers: []` | none | ~0.9 KB/entry | 190 KB (limit=100 page) |
| Registry `GET /v0/servers/{name}/versions[/{v}]` | 200 | 404 problem+json | none | 0.7-4 KB | 4 KB |
| PyPI `GET /pypi/{p}/json` | 200 | 404 `{"message": "Not Found"}` | none | 8-190 KB | 3.87 MB (botocore) |
| PyPI `GET /pypi/{p}/{v}/json` | 200 | 404 same body | none | ~10 KB | |
| PyPI `GET /simple/{p}/` (JSON) | 200 | not tested | none | ~100 KB (urllib3) | |
| PyPI `GET /integrity/.../provenance` | 200 | 404 `{"message": "No provenance available for <file>"}` | none | ~9.5 KB | |
| npm `GET /{pkg}` (full packument) | 200 | 404 `{"error":"Not found"}` | none | 336-824 KB | 11.2 MB (@types/node) |
| npm `GET /{pkg}` abbreviated | 200 | not tested | none | 343 KB (express) | 2.3 MB (@types/node) |
| npm `GET /{pkg}/{version or tag}` | 200 | 404 `"version not found: <v>"` or `"Not Found"` (missing package) | none | 2-7 KB | 25 KB (aws-cdk-lib) |
| OSV `POST /v1/query` | 200 (`{}` when nothing matches) | 200 `{}` (indistinguishable from no advisories) | none | 2 B (latest versions) to 3.98 MB | 3,983,856 B (tensorflow 2.4.0) |

No response from any of the three services carried `X-RateLimit-*`, `RateLimit-*` or
`Retry-After` headers, including a 55-page registry crawl (limit=100, 0.3 s pause between
requests). No 429s were seen. Sizes are uncompressed bodies.

## MCP Registry (registry.modelcontextprotocol.io)

API: OpenAPI 3.1 at `/openapi.json` and `/openapi.yaml` (info.version `1.0.0`, title
"Official MCP Registry"). `/docs` is an HTML page. `/v0` and `/v0.1` expose identical
read paths; `/v0.1/servers?search=vuln-triage` returned the same body as `/v0`.

### List and search: `GET /v0/servers`

Parameters (from the OpenAPI spec, behaviour confirmed live):

- `search`: "Search servers by name (substring match)". Name only: `search=CISA` did not
  return `io.github.kimmawla/vuln-triage-mcp`, whose description mentions CISA. Case-insensitive
  (`search=EPSS` matched a third-party entry whose name contains `epss`). Fewer than 3 characters after trimming
  is a 422: `"search must contain at least 3 characters after trimming surrounding whitespace"`.
- `limit`: integer, default 30, minimum 1, maximum 100. `limit=0` and `limit=101` are 422
  `"validation failed"`.
- `cursor`: opaque string; observed values look like `<name>:<version>` of the last item on
  the page (shape in `registry_servers_page.json`). Pass `metadata.nextCursor` back verbatim (URL-encoded).
  **An invalid cursor is not an error**: `cursor=zzz-not-a-cursor` returned 200 with
  `{"servers": [], "metadata": {"count": 0}}`.
- `version`: `latest` or an exact version. **Without it, a listing returns one item per
  published version**: `search=CISA` returned the same server name up to 8 times.
- `updated_since`: RFC 3339 timestamp; `updated_since=yesterday` is a 400 with
  `"Invalid updated_since format: expected RFC3339 timestamp (e.g., 2025-08-07T13:15:04.280Z)"`.
  Per the spec, it forces `include_deleted` to true.
- `include_deleted`: boolean; deleted entries are excluded by default.

Response shape (fixtures `registry_servers_search.json`, `registry_servers_page.json`):

```
{ "servers": [ { "server": {...}, "_meta": {...} } ],
  "metadata": { "count": <int>, "nextCursor": <string, absent on the last page> } }
```

`metadata.count` is the number of items in this page, not a total. Pages are sorted by
name, then version. Empty result: `{"servers": [], "metadata": {"count": 0}}` (fixture
`registry_servers_empty.json`).

Pagination test: `search=github&limit=3` gave a `nextCursor` equal to the third (third-party)
item's `<name>:<version>`; passing it returned the next 3 items and a new cursor.

### Single server and versions

There is **no** `GET /v0/servers/{name}` endpoint: both `%2F`-encoded and raw slash forms
return 404 problem+json `"Endpoint not found. See /docs for the API documentation."`
(fixture `registry_endpoint_not_found.json`). Use:

- `GET /v0/servers/{name}/versions`: list shape as above, all versions of one server.
  **Not paginated, and `limit` is ignored**: one third-party server returned all 1,133 versions
  in one 1,990,901-byte response, with and without `limit=5` (`metadata` has `count` only).
- `GET /v0/servers/{name}/versions/latest` or `/versions/{exact version}`: one
  `{"server": ..., "_meta": ...}` object, no `metadata` (fixture `registry_server_version.json`).

The name is percent-encoded with `/` as `%2F`. Both take `include_deleted` (default false).
Name lookup is **case-sensitive** (tested 2026-11-02): only the exact stored case returns 200.
`io.github.kimmawla%2Fvuln-triage-mcp` is 200, while `io.github.KimMawla%2F...`,
`IO.GITHUB.KIMMAWLA%2FVULN-TRIAGE-MCP` and `io.github.kimmawla%2FVuln-Triage-MCP` are 404.
A third-party `io.github.<owner>` entry whose owner has capital letters was 200 in its stored
case and 404 with the owner lowercased.
`search` is case-insensitive (`KIMMAWLA` and `kimmawla` both find the entry).
`/versions/latest?include_deleted=true` returns a deleted server's latest version: for one
third-party deleted server, 200 with `status` `deleted` and `isLatest` true (404 without the
flag). A dot-segment name (`..%2F..%2Fx`) returned the ordinary 404 "Server not found".

Missing server, missing version, or **deleted server without `include_deleted=true`**: all
return 404 `application/problem+json` `{"title": "Not Found", "status": 404, "detail":
"Server not found"}` (fixture `registry_server_not_found.json`). Observed with a version of
that same third-party deleted server: 404 by default, 200 with `?include_deleted=true` (shape in
synthetic fixture `registry_server_version_deleted.json`). A deleted server is therefore indistinguishable
from a nonexistent one unless `include_deleted=true` is sent.

### Item fields

`server` (publisher-supplied server.json; every text field is untrusted):

| Field | Type | Notes |
|---|---|---|
| `$schema` | string | e.g. `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json` |
| `name` | string | e.g. `io.github.kimmawla/vuln-triage-mcp`; owner case is kept (mixed-case `io.github.<Owner>/...` names were seen). OpenAPI `ServerJSON.name`: pattern `^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`, minLength 3, maxLength 200. Domain namespaces are common (`ai.<domain>/...`, `com.<domain>/...`) |
| `description`, `title` | string | `title` optional |
| `version` | string | |
| `repository` | object, optional | `url` (string), `source` (`github` or `gitlab` seen), and optionally `id` (a numeric string) and `subfolder` (string, a directory for a monorepo) |
| `websiteUrl` | string, optional | |
| `icons` | array, optional | |
| `packages` | array, optional | see below |
| `remotes` | array, optional | `type` `streamable-http` or `sse`, `url`, and optionally `variables` and `headers`; see "Remote URLs" below |
| `_meta` | object, optional | only key seen: `io.modelcontextprotocol.registry/publisher-provided` |

`packages[]` keys seen: `registryType`, `identifier`, `version`, `transport` (`type`:
`stdio` or `streamable-http`), and optionally `registryBaseUrl`, `runtimeHint` (`npx`,
`uvx`, `node`, `docker`), `runtimeArguments`, `packageArguments`, `environmentVariables`,
`fileSha256`. `version` is absent for every `oci` and `mcpb` package seen (the version is in
the identifier or URL). `registryBaseUrl` values seen: only `https://registry.npmjs.org`
and `https://pypi.org`.

`registryType` values seen: `npm`, `pypi`, `oci`, `mcpb`, `nuget`, `cargo`.

Response-level `_meta["io.modelcontextprotocol.registry/official"]` (registry-managed):

| Field | Type | Required (OpenAPI) |
|---|---|---|
| `status` | `active` \| `deprecated` \| `deleted` | yes |
| `statusChangedAt` | RFC 3339 string | yes |
| `publishedAt` | RFC 3339 string | yes |
| `isLatest` | boolean | yes |
| `updatedAt` | RFC 3339 string | no |
| `statusMessage` | string | no; free text, untrusted |

Status values come from the OpenAPI enum and were all observed live: in the first 40 pages
of `include_deleted=true` (4,000 entries, names `ac.*` to `ai.*`), 3,797 active, 78
deprecated, 125 deleted. Real `statusMessage` values seen take forms such as
`"Consolidated onto <other server name> (<publisher>)"` and `"Renamed to <other server name>"`.
Deprecated servers still appear in default searches (shape in synthetic fixture
`registry_server_version_deprecated.json`).

Docs mismatch: `docs/reference/server-json/official-registry-requirements.md` shows
`status` and the timestamps directly under the response-level `_meta`. Live responses nest
them under the `io.modelcontextprotocol.registry/official` key.

### Sample composition (not the whole registry)

- First 4,000 entries alphabetically with `include_deleted=true` (1,181 names, all
  `ac.*`-`ai.*` domain namespaces): 86% of latest versions are remote-only.
- First 1,500 `search=io.github&version=latest` entries (names `io.github.0...` to
  `io.github.B...`): 36% remote-only (`remotes` and no `packages`); packages: npm 521,
  pypi 319, mcpb 69, oci 35, nuget 10, cargo 5.

### Remote URLs (same two samples, latest versions, 1,755 remote URLs)

- Scheme: all 1,755 `https`. No userinfo (`user:pass@`), no IP-literal hosts, no explicit
  port except one templated `{HAPI_PORT}`.
- 20 URLs are templates with `{name}` placeholders declared in `remotes[].variables`
  (e.g. `public_id`, `tenant`, `api_host`, `private_cloud_url`, `api_key`). In some the
  placeholder is the whole host or port (`{api_host}`, `{HAPI_FQDN}:{HAPI_PORT}`), so the host
  cannot be known statically; Python's `urlsplit(...).port` raises on `{HAPI_PORT}`.
- One URL had a credential-named query parameter (`api_key`), and its value was a
  `{api_key}` placeholder, not a literal secret.
- Host vs namespace: for domain namespaces, the host equals or is a subdomain of the
  namespace's first two labels reversed (`ai.zqvex` -> `zqvex.ai`) in 1,052 of 1,083
  URLs. Mismatches seen include platform hosts (`*.workers.dev`) and namespaces whose first two
  labels are not the registrable domain (a three-label `ac.<name>.sh` namespace with host
  `api.<name>.sh`). For `io.github.<owner>` names only 77 of 672 hosts contained the owner;
  the rest were third-party vendor hosts or platform hosts (`workers.dev`, ...).

### Status changes

The OpenAPI spec has authenticated `PATCH /v0/servers/{serverName}/status` and
`PATCH /v0/servers/{serverName}/versions/{version}/status` endpoints (body enum `active`,
`deprecated`, `deleted`); the spec does not say who may call them. Observed `deleted`
entries include rename and consolidation messages ("Renamed to <other server name>"),
so `deleted` is not only the moderation removal described in the moderation policy.

### Publishing and verification rules (registry docs)

Source: `modelcontextprotocol/registry` at commit `01e5c936ad3048d16562be503d879e523e36d267`
(main, 2026-10-31).

From `docs/modelcontextprotocol-io/authentication.mdx`:

- GitHub-based auth: name must be `io.github.<username>/*` or `io.github.<orgname>/*`. Org
  namespaces need the publisher to be an org **Owner**.
- Domain-based auth (DNS TXT record on the apex domain, or HTTP): name must be
  `<reverse-domain>.*/*`, e.g. `io.modelcontextprotocol/everything`.

Which namespaces a domain proof grants (registry source at the same commit,
`internal/api/handlers/v0/auth/common.go` `BuildPermissions` and `ReverseString`, plus
`dns.go` and `http.go`):

- The domain is reversed label by label (`example.com` -> `com.example`).
- DNS proof grants `com.example/*` and `com.example.*` (extra trailing labels, which read as
  subdomains: `com.example.api` is `api.example.com`). The code comment: "DNS implies a hierarchy
  where subdomains are treated as part of the parent domain".
- HTTP proof (`https://<domain>/.well-known/mcp-registry-auth`) grants `com.example/*` only
  (`allowSubdomains := false`).
- `github.io` and its subdomains are refused for domain auth; `io.github.*` names use GitHub auth.
- So a namespace with more labels than the proven domain is allowed (DNS only), and the proven
  domain may be shorter than the namespace.

How `io.github.<owner>` permission is compared (read 2026-11-04, same commit): **case-sensitive**.

- GitHub token auth (`internal/api/handlers/v0/auth/github_at.go` `buildPermissions`) grants
  `io.github.<login>/*` for `user.Login` from `GET /user`, plus `io.github.<org.Login>/*` for each
  org where the caller is Owner. GitHub OIDC (`github_oidc.go` `buildPermissions`) grants
  `io.github.<repository_owner>/*` from the token claim. Each login is checked against
  `^[a-zA-Z0-9-]+$` and used as given; nothing lowercases it.
- `publish.go` calls `HasPermission(input.Body.Name, ...)` on the name as submitted; `edit.go`
  calls it on the stored name. `internal/auth/jwt.go` `isResourceMatch` is
  `strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*"))`: a byte comparison. No
  `ToLower` or `EqualFold` is on this path (the only `EqualFold` is the `Bearer ` prefix; the only
  `ToLower` is `isGitHubPagesDomain`).
- So `io.github.Foo/x` can be published only with a grant whose login is exactly `Foo`. A name
  whose owner differs only in case needs a login in that exact case. Which case GitHub returns for
  `login` and `repository_owner` is GitHub's behaviour, not checked here.
- Domain auth is case-sensitive too: `BuildPermissions` reverses the domain with `ReverseString`
  and does not lowercase it.
- The blocklist check (`jwt.go` `GenerateTokenResponse`) runs through the same `HasPermission`,
  so it is case-sensitive as well; `internal/auth/blocks.go` `BlockedNamespaces` is empty at this
  commit.
- This matches the lookup observation above (name lookup is case-sensitive). In the 2026-11-03
  crawl, 5 of the 7 TS001 pairs are two names whose `io.github` owners differ only in case
  (`scripts/precision_report.py`).

### Ownership verification code

Read at the same commit, `internal/validators/`. `validators.go` `validateRegistryOwnership` calls
`package.go` `ValidatePackage` for every package, which dispatches on `registryType` to
`registries/{npm,pypi,mcpb,oci,nuget,cargo}.go`. All of it runs only when the registry's
`cfg.EnableRegistryValidation` is set (`ValidatePublishRequest`); the production setting is not
visible.

| Question the docs left open | What the code does | Docs agree? |
|---|---|---|
| Whitespace after `mcp-name:` | `mcpname.go` `containsMCPNameToken` searches for the exact string `"mcp-name: " + serverName`: one space, no tabs, no other spacing | Docs show one space; never say others fail |
| PyPI case sensitivity | `strings.Index`: case-sensitive | Not stated |
| npm case sensitivity | `npm.go` `validateNPMPackage`: `npmResp.MCPName != serverName`, exact. An empty `mcpName` is reported as missing | Not stated |
| The "HTML tag" boundary | `isMCPNameBoundary`: end of content, **any byte that is not a server-name character** (`[A-Za-z0-9._/-]`, `isServerNameChar`), or a `-->` / `--!>` prefix. So `)`, `,`, `"`, `'`, `!` and non-ASCII all end the name; `.`, `_`, `/`, `-` glue it (except `-->`, `--!>`). Every occurrence is tried | **No**: docs list only newline, whitespace, an HTML tag, or `-->`. The code accepts more (any non-name character, and `--!>`) |
| Which version is read | PyPI: `GET {base}/pypi/{id}/{version}/json`, `info.description`. npm: `GET {base}/{id}/{version}`, `mcpName`. A version is required for both (`ErrMissingVersionForPyPi`, `ErrMissingVersionForNPM`) | Docs say "README"/"package.json" without a version |
| mcpb URL rule | `mcpb.go` `ValidateMCPB`: `fileSha256` must be non-empty; `registryBaseUrl` must be empty; `validateMCPBUrl`: `url.Parse`, lowercased `URL.Host` (port included) must be `github.com`, `www.github.com`, `gitlab.com` or `www.gitlab.com`; the decoded path must match `isValidGitHubReleaseURL` (`/owner/repo/releases/download/tag/file`) or `isValidGitLabReleaseURL` (`/.../-/releases/tag/downloads/file` or `/.../-/package_files/id/download`); scheme `https`; `strings.Contains(strings.ToLower(identifier), "mcp")`, i.e. **case-insensitive, anywhere in the URL**; then a HEAD request must return 200 or a 3xx with `Location` | Partly: docs say only "MUST contain the string mcp" (no case rule) and "GitHub or GitLab releases" |
| fileSha256 format | Not checked on publish: `ValidateMCPB` checks only non-empty. The schema (`schemas/2025-12-11.json`) has `^[a-f0-9]{64}$`, but publish uses `ValidationSchemaVersionAndSemantic`, which does not set `ValidateSchema`, so full schema validation does not run | Docs say "MUST include a fileSha256", no format |
| fileSha256 on other types | npm, PyPI, OCI, NuGet and cargo packages must **not** have `fileSha256` | Not stated in package-types.mdx |
| OCI marker | `oci.go` `ValidateOCI` reads `configFile.Config.Labels["io.modelcontextprotocol.server.name"]` (an image config label) and compares with `!=` | **No**: docs call it an "annotation"; the code reads a label |
| Missing package vs missing version | PyPI and npm both send a HEAD to the package-level endpoint after a 404 | Not stated |

Verifier source files and their SHA-256 at commit `01e5c936ad3048d16562be503d879e523e36d267`.
`scripts/check_registry_drift.py` reads this table, fetches the same paths at the registry's
current `main`, and reports any file whose hash changed. Run it by hand before each release.

<!-- verifier-hashes:start -->
| Path | SHA-256 at 01e5c936 |
|---|---|
| `internal/validators/validators.go` | `7f1170c67b253547fe5819a895d9377f851e649299a8a5af1edea79253e2ae13` |
| `internal/validators/package.go` | `64154cd14934e85b6d17cbd8964dcc8f5d9bb30337ab50bfe21bc0a21c4c1ab5` |
| `internal/validators/validation_types.go` | `1f32bb4c600cd1923955e4a1ba299552ad9805d484b3da88f4c25b87bca57f59` |
| `internal/validators/schemas/2025-12-11.json` | `2e1e2dc758185bfc91023df4e5ace0e1c1bdb7b7b3d6614bb9ac6b9e9a9c2f68` |
| `internal/validators/registries/mcpname.go` | `2a6f4ff213d11cc4ed886646ff29295ed05966c721bc2489ef3748c583592571` |
| `internal/validators/registries/pypi.go` | `017414f28139392ecbe4329f44d5c0500e18937f2adb7a061972c24b4ac97d69` |
| `internal/validators/registries/npm.go` | `bb526ac80429634c334e3f77220319d48727f0e60a5cba5966de1434562901dc` |
| `internal/validators/registries/mcpb.go` | `ae36edf7db11ea11537abda07fb8ebb873ac0c47f00d574bd2ab756cdffe251b` |
| `internal/validators/registries/oci.go` | `e5a64325f15747501910dfea1c644c1c0d76dcd8e4d6392b19ffde07630fb07e` |
| `internal/validators/registries/nuget.go` | `ff61203e2b092e64273461a209385c2592f87005f321ab1c19e7d7b15029855f` |
| `internal/validators/registries/cargo.go` | `3caa5dee999bf52cfbfcc014eda74fee31197f04945d3e42bca24ea1a8b0f48b` |
| `internal/api/handlers/v0/publish.go` | `96191a5ee5382669257b667ac85bd98fece85ae22a456fb2e27351ade781a296` |
| `internal/auth/jwt.go` | `d0bcf177130a59f3bab2b319aa111000bed80412b0c1b8cc7ebe95874c5d229d` |
| `internal/api/handlers/v0/auth/github_at.go` | `6840ad3623997ea134a0ead5bfa390c0438746400a52d29b067b3c4d8207bdb1` |
| `internal/api/handlers/v0/auth/github_oidc.go` | `41248e01371d86d5dacc2b9d28084ec414a7d0dc55a09a7560122a824c015878` |
<!-- verifier-hashes:end -->

From `docs/reference/server-json/official-registry-requirements.md`:

- Allowed registry base URLs: npm `https://registry.npmjs.org`; PyPI `https://pypi.org`;
  NuGet `https://api.nuget.org/v3/index.json`; Cargo `https://crates.io`; OCI `docker.io`,
  `ghcr.io`, `quay.io`, `*.pkg.dev`, `*.azurecr.io`, `mcr.microsoft.com`; MCPB GitHub and
  GitLab releases only.
- `server._meta`: only `io.modelcontextprotocol.registry/publisher-provided` is kept;
  other keys are dropped. Limited to 4096 bytes of JSON.

Ownership verification per package type, from `docs/modelcontextprotocol-io/package-types.mdx`:

| registryType | What must be present to verify | Visible via an allowed host? |
|---|---|---|
| `npm` | `package.json` `mcpName` equal to the server name | Yes: `mcpName` is in `registry.npmjs.org/{pkg}/{version}` (fixture `npm_version_mcp_server.json`) |
| `pypi` | `mcp-name: <server name>` in the README (PyPI description), may be inside an HTML comment; must be followed by a newline, whitespace, an HTML tag, or `-->` | Yes: in `info.description` of `pypi.org/pypi/{p}/json`; present in vuln-triage-mcp 0.1.0 |
| `nuget` | `mcp-name: <server name>` in the package README | No (api.nuget.org not allowed) |
| `cargo` | `mcp-name: <server name>` as **visible** text in the README (crates.io strips HTML comments) | No (crates.io not allowed) |
| `oci` | image annotation `io.modelcontextprotocol.server.name` equal to the server name | No (container registries not allowed) |
| `mcpb` | identifier URL contains `mcp`; `fileSha256` required. "The MCP Registry does not validate this hash" | No (github.com / gitlab.com not allowed) |

From `docs/modelcontextprotocol-io/moderation-policy.mdx`: removal sets `status` to
`"deleted"` and the metadata stays readable through the API. The policy is "quite
permissive": only illegal content, malware, spam and broken servers are removed.

## PyPI (pypi.org)

### Project: `GET /pypi/{project}/json`

Fetched for `vuln-triage-mcp`, `requests`, `urllib3`, and `Requests` (case-insensitive:
same body as `requests`). Fixtures `pypi_project_self.json`, `pypi_project_requests.json`.

Top-level keys: `info`, `last_serial` (int), `ownership`, `releases`, `urls`,
`vulnerabilities`.

- **Owner info**: `ownership` is `{"organization": null | ..., "roles": [{"role": "Owner",
  "user": "<username>"}]}`. Seen: one owner for vuln-triage-mcp, three for requests and
  urllib3; `organization` was null for all three. This is the account-level view.
- `info.author`, `author_email`, `maintainer`, `maintainer_email` are free text from
  package metadata (e.g. `"zqvex-person-1 <...>, zqvex-person-2 <...>"`, a `Name <address>`
  list), often null.
  Not account identities.
- `info.project_urls`: dict with publisher-chosen labels (`Repository`, `Source`, `Code`,
  `Issue tracker`, ...). No fixed key for the repository URL. `home_page` was null for all three.
- `info.description` (string, the README) and `info.description_content_type`
  (`text/markdown`).
- `info.classifiers`: list of strings, empty for vuln-triage-mcp.
- `info.license` (null or string) and `info.license_expression` (SPDX string or null);
  packages fill one or the other.
- `info.version`: latest version. `info.yanked` (bool), `info.yanked_reason` (null).
- `info.downloads`: always `{"last_day": -1, "last_month": -1, "last_week": -1}`. **No
  download data.**
- `releases`: dict version -> list of files. Some versions have **no files** (requests
  `0.0.1`, `0.12.01`, `2.15.0`; urllib3 `0.3`, `0.3.1`, `0.4.0`), so they have no upload time.
- `urls`: files of the latest version only.
- File keys: `filename`, `packagetype` (`bdist_wheel`, `sdist`), `python_version`,
  `requires_python`, `size` (int), `upload_time` (`2026-10-21T21:31:59`, no zone),
  `upload_time_iso_8601` (`2026-10-21T21:31:59.714542Z`), `url`, `yanked`,
  `yanked_reason`, `comment_text`, `downloads` (int), `has_sig` (false for all seen),
  `md5_digest`, `digests` (`blake2b_256`, `md5`, `sha256`), and `core-metadata`
  (`{"sha256": ...}`).
- `vulnerabilities`: **for the latest version only**. Project-level `requests` returned
  `[]`, while `GET /pypi/requests/2.32.3/json` returned 4 items with keys `id`, `aliases`,
  `details`, `summary` (null), `fixed_in`, `link`, `source`, `withdrawn` (null).

There is no project creation date. The earliest upload must be computed from `releases`,
ignoring versions with no files.

### Release: `GET /pypi/{project}/{version}/json`

Same as the project response but without `releases`; `vulnerabilities` are for that
version (fixture `pypi_release_requests_2.32.3.json`).

- A version that exists with **no files** returns 200 with `"urls": []` (requests `0.0.1`,
  fixture `pypi_release_zero_files.json`).
- A missing version of an existing project (`/pypi/requests/9.9.9/json`) and a missing project
  both return 404 `{"message": "Not Found"}`: the release endpoint cannot tell them apart.
  The project endpoint's status code can.
- The provenance URL for a file is `/integrity/{project}/{version}/{filename}/provenance`, with
  `filename` from `urls[]`. That matches the `provenance` links the Simple API gives, so the
  Simple API is not needed for it.

### Provenance and attestations

- **The JSON API above has no provenance or attestation fields.**
- Simple API, JSON form: `GET /simple/{project}/` with
  `Accept: application/vnd.pypi.simple.v1+json` (`meta.api-version` `1.4`). Top-level:
  `name`, `files`, `versions`, `meta`, `project-status` (`{"status": "active"}`). File keys:
  `filename`, `url`, `hashes`, `requires-python`, `size`, `upload-time`, `yanked`,
  `core-metadata`, `data-dist-info-metadata`, `provenance`. `provenance` is a URL on pypi.org
  or `null` (fixtures `pypi_simple_urllib3.json`, `pypi_simple_self.json`).
- Provenance: `GET /integrity/{project}/{version}/{filename}/provenance` with
  `Accept: application/vnd.pypi.integrity.v1+json`. Body: `{"version": 1,
  "attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": "urllib3/urllib3",
  "workflow": "publish.yml", "environment": "publish"}, "attestations": [{"version",
  "envelope": {"statement", "signature"}, "verification_material": {"certificate",
  "transparency_entries"}}]}]}` (fixture `pypi_provenance_urllib3.json`).
- No provenance: 404 `{"message": "No provenance available for requests-2.32.3-py3-none-any.whl"}`.
- vuln-triage-mcp 0.1.0: `provenance` is `null` for both files.

### Headers

`cache-control: max-age=900, public` (simple: 600), `etag`, `x-pypi-last-serial`,
`x-cache`, `x-cache-hits`, `vary: Accept-Encoding` (simple adds `Accept`). The 404 has no
`cache-control`.

## npm (registry.npmjs.org)

Fetched: `express` (unscoped), `@modelcontextprotocol/sdk` (scoped), `esbuild` (has an
install script), `@types/node` (size), and two third-party MCP server packages listed in the
registry (one unscoped, one scoped; not named here).

### Scoped names in the URL

All of these returned the same 200 body for `@modelcontextprotocol/sdk`:
`/@modelcontextprotocol%2fsdk`, `/@modelcontextprotocol%2Fsdk`,
`/@modelcontextprotocol/sdk`, `/%40modelcontextprotocol%2Fsdk`. Version documents also
work with the raw slash (`/@modelcontextprotocol/sdk/latest`). Recommended form: keep `@`
and encode the slash as `%2F` (`/@scope%2Fname`). That is the form npm itself uses in
attestation URLs (`/-/npm/v1/attestations/@modelcontextprotocol%2fsdk@1.32.2`).

### Full packument: `GET /{pkg}`

Top-level: `_id`, `_rev`, `name`, `dist-tags`, `versions`, `time`, `maintainers`,
`repository`, `description`, `readme`, `readmeFilename`, `author`, `bugs`, `homepage`,
`keywords`, `license`, `users`, and sometimes `contributors`. Fixtures
`npm_packument_express.json`, `npm_packument_scoped_sdk.json`.

- `dist-tags`: dict tag -> version (express: `latest` `5.3.0`, `latest-4` `4.22.3`).
- `time`: dict with `created`, `modified`, and one key per version (ISO 8601 with `Z`).
  express has 322 keys for 290 versions. No `unpublished` key was seen.
- `maintainers`: list of `{name, email}`.
- `repository`: `{"type": "git", "url": "git+https://github.com/expressjs/express.git"}`
  (note the `git+` prefix).

Version document (inside `versions`, or `GET /{pkg}/{version|tag}`; fixtures
`npm_version_*.json`):

- `scripts`: dict. Install hooks are the `preinstall`, `install`, `postinstall` keys; esbuild
  0.28.2 has `{"postinstall": "node install.js"}`. Neither express nor the sdk had install
  hooks in any version.
- **`hasInstallScript` is absent from full version documents** even for esbuild. It appears
  only in the abbreviated format (`true` for esbuild).
- `dist`: `integrity` (`sha512-...`), `shasum` (sha1 hex), `tarball` (URL), `fileCount`,
  `unpackedSize`, `signatures` (`[{keyid, sig}]`; the sdk has two), and when published
  with provenance, `attestations`: `{"url": ".../-/npm/v1/attestations/<pkg>@<ver>",
  "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}`. The attestation URL
  is on registry.npmjs.org.
- `_npmUser`: who published. express 5.3.0: `{"name": "GitHub Actions", "email":
  "npm-oidc-no-reply@github.com", "trustedPublisher": {"id": "github", "oidcConfigId":
  ...}, "approver": {...}}`. (In the committed fixtures these service values, like every
  `_npmUser` value, are replaced with invented `zqvex-ci-*` values; see the fixture index.)
- `mcpName`: present on MCP server packages, as a registry server name string (shape in
  synthetic fixture `npm_version_mcp_server.json`).
- `gitHead`, `_nodeVersion`, `_npmVersion`, `_hasShrinkwrap`, `_npmOperationalInternal`.

### Abbreviated metadata

`Accept: application/vnd.npm.install-v1+json`. Top-level only `name`, `dist-tags`,
`versions`, `modified`. Version keys: `name`, `version`, `dist`, dependency maps,
`engines`, `bin`, `funding`, `hasInstallScript`. **No `time` (except top-level
`modified`), `maintainers`, `repository`, `scripts`, or `_npmUser`** (fixtures
`npm_abbreviated_express.json`, `npm_abbreviated_esbuild.json`).

### Sizes (uncompressed)

| Request | Bytes |
|---|---|
| `express` full | 823,554 (106,208 gzip) |
| `express` abbreviated | 342,878 |
| `esbuild` abbreviated | 889,133 |
| `@modelcontextprotocol/sdk` full | 335,992 |
| `@types/node` full | 11,183,996 (1,425,987 gzip) |
| `@types/node` abbreviated | 2,334,287 |
| `/{pkg}/latest` | 3,513 to 6,524 |

### Version documents: missing versions (tested 2026-11-02)

`GET /{pkg}/{version or tag}` 404 bodies are bare JSON strings, not objects, and they tell a
missing version apart from a missing package:

| Request | Status | Body |
|---|---|---|
| `/express/0.0.0-no-such-version` | 404 | `"version not found: 0.0.0-no-such-version"` (fixture `npm_version_not_found.json`) |
| `/express/no-such-tag` | 404 | `"version not found: no-such-tag"` |
| `/@modelcontextprotocol%2fsdk/0.0.0-no-such-version` | 404 | `"version not found: 0.0.0-no-such-version"` |
| `/express/%5E4.0.0` (a range) | 404 | `"version not found: ^4.0.0"`: ranges are not resolved |
| `/no-such-package-zzqq-2026/1.0.0` and `/.../latest` | 404 | `"Not Found"` (fixture `npm_version_package_not_found.json`) |

The version document has no date field: `time` exists only in the full packument.
`_npmOperationalInternal.tmp` embeds a number that looks like a timestamp
(`tmp/express_5.3.0_1791550614422_...`), but it is undocumented.

### Attestations

`GET /-/npm/v1/attestations/{pkg}@{version}` (the `dist.attestations.url`): 200 with
`{"attestations": [...]}`, each item having a `predicateType` (express 5.3.0:
`https://github.com/npm/attestation/tree/main/specs/publish/v0.1` and
`https://slsa.dev/provenance/v1`). Sizes: 14,493 bytes (express@5.3.0), 15,167 bytes
(@modelcontextprotocol/sdk@1.32.2). A version without attestations (react@19.0.0): 404
`{"error":"Not found"}`, the same body as a missing package.

### Errors and headers

Missing package, scoped or not: 404 `{"error":"Not found"}` (fixture `npm_not_found.json`).
Headers: `cache-control: public, max-age=300`, `etag`, `last-modified`, `cf-cache-status`,
`age`, `vary: accept-encoding, accept`.

## OSV.dev (api.osv.dev)

`POST /v1/query` with `Content-Type: application/json`, measured 2026-11-02 with curl. Body:
`{"package": {"name": ..., "ecosystem": "PyPI" | "npm"}, "version": ...}`; omit `version` for
all versions; add `"page_token"` from the previous response's `next_page_token` for the next page.
`GET /v1/query` is 405. No rate-limit headers; responses carry `grpc-status: 0`.

| Query | Status | Bytes | Vulns | Next page token |
|---|---|---|---|---|
| six 1.17.0 (latest; small package) | 200 | 2 (`{}`) | 0 | no |
| django 6.1.2 (latest; large framework) | 200 | 2 (`{}`) | 0 | no |
| vuln-triage-mcp 0.1.0 (latest) | 200 | 2 (`{}`) | 0 | no |
| django, all versions | 200 | 917,110 | 324 | no |
| django 1.2 | 200 | 325,336 | 93 | no |
| django 3.2.0 | 200 | 239,175 | 66 | no |
| tensorflow 2.4.0 | 200 | 3,983,856 | 760 | no |
| requests 2.19.0 | 200 | 35,372 | 10 | no |
| npm express 4.0.0 | 200 | 7,584 | 3 | no |
| npm lodash 4.17.0 | 200 | 35,358 | 10 | no |

- A latest version with no advisories returns `{}`: no `vulns` key at all.
- A package OSV does not know (`no-such-package-zzqq-2026` 1.0) also returns 200 `{}`, so "no
  advisories" and "no such package" look the same.
- Wrong ecosystem case (`"PyPi"`): 400 `{"code":3,"message":"invalid ecosystem"}`.
- A made-up `page_token`: 400 `{"code":3,"message":"invalid cursor"}` (fixture
  `osv_query_invalid_cursor.json`).
- A single versioned page can be large: tensorflow 2.4.0 returned 760 advisories, 3.98 MB, in one
  page with no token.
- Pagination behaviour (page sizes, a misnamed token field returning page 1 again) is recorded in
  the vuln-triage-mcp project's notes (2026-10-21); it was not re-tested here.

## audit_package data (measured 2026-11-04)

Measured with curl for docs/rules-package.md. Sizes are uncompressed bodies (no
`Accept-Encoding` sent). Each line is `status bytes URL`, printed by
`curl -sS -o <file> -w "%{http_code} %{size_download} B  <url>\n" <url>`.

### Resolving the latest version

```
# npm: the dist-tag works in place of a version and returns that version's document
200 3837 B   https://registry.npmjs.org/express/latest
200 6524 B   https://registry.npmjs.org/@modelcontextprotocol%2Fsdk/latest
200 25414 B  https://registry.npmjs.org/aws-cdk-lib/latest
404 11 B     https://registry.npmjs.org/no-such-package-zzqq-2026/latest    ("Not Found")

# PyPI: there is no latest alias; info.version is only in the project JSON
404 24 B     https://pypi.org/pypi/requests/latest/json                     ({"message": "Not Found"})
200 8131 B   https://pypi.org/pypi/vuln-triage-mcp/json
200 192973 B https://pypi.org/pypi/requests/json
200 630589 B https://pypi.org/pypi/django/json
200 3319234 B https://pypi.org/pypi/boto3/json
200 3729122 B https://pypi.org/pypi/numpy/json
200 3867551 B https://pypi.org/pypi/botocore/json
```

- npm `/{pkg}/latest` is the cheapest bounded way: one request, and the body is the version
  document itself (its `version` field names the resolved version). Largest seen 25,414 B,
  under the 256 KiB npm cap. A tag-resolved document is identical to the exact-version one
  (`/request/latest` and `/request/2.88.2`: same 3,712 B).
- PyPI has no per-version way to resolve the latest version. The project JSON is the only JSON
  source of `info.version` (`requests`: `2.34.2`), and its size grows with release history.
  **It exceeds the 512 KiB PyPI cap for large projects** (django 630,589 B; boto3, numpy,
  botocore 3.3-3.9 MB). The Simple API JSON is project-level too (botocore 2,607,450 B) and
  has a `versions` list but no latest marker.

### Yanked (PyPI) and deprecated (npm)

```
200 10298 B  https://pypi.org/pypi/requests/2.32.0/json     (a yanked release)
200 10145 B  https://pypi.org/pypi/requests/2.32.3/json
200 3712 B   https://registry.npmjs.org/request/2.88.2       (a deprecated package)
```

- PyPI release JSON: `info.yanked` and `info.yanked_reason` describe **that** version
  (2.32.0: `true`, `"Yanked due to conflicts with CVE-2024-35195 mitigation"`; `info.version`
  is `2.32.0`). Each `urls[]` file carries the same `yanked`/`yanked_reason`. 2.32.3: `false`,
  `null`.
- npm version document: `deprecated` is a string, the publisher's message
  (`"request has been deprecated, see https://github.com/request/request/issues/3142"`), and
  is absent on a version that is not deprecated (express 5.3.0, react 19.0.0). The same
  message appears on `/request/latest`. An empty string was not observed.

### Provenance

```
# npm: the version document already says whether provenance exists
200 3837 B   https://registry.npmjs.org/express/5.3.0      dist.attestations present
200 1818 B   https://registry.npmjs.org/react/19.0.0       no dist.attestations key
200 3712 B   https://registry.npmjs.org/request/2.88.2     no dist.attestations key

# PyPI: one request per file, Accept: application/vnd.pypi.integrity.v1+json
404 80 B     https://pypi.org/integrity/vuln-triage-mcp/0.1.0/vuln_triage_mcp-0.1.0-py3-none-any.whl/provenance
404 70 B     https://pypi.org/integrity/vuln-triage-mcp/0.1.0/vuln_triage_mcp-0.1.0.tar.gz/provenance
200 9533 B   https://pypi.org/integrity/urllib3/2.8.0/urllib3-2.8.0-py3-none-any.whl/provenance
200 9611 B   https://pypi.org/integrity/urllib3/2.8.0/urllib3-2.8.0.tar.gz/provenance
404 4871 B   https://pypi.org/integrity/vuln-triage-mcp/0.1.0/no-such-file.whl/provenance
200 63184 B  https://pypi.org/pypi/numpy/2.5.4/json       (66 files in urls[])
```

- npm: `dist.attestations.provenance.predicateType` (`https://slsa.dev/provenance/v1`) when
  published with provenance; without it, `dist` has no `attestations` key. No extra request
  is needed.
- PyPI: a file with no provenance is a JSON 404 `{"message": "No provenance available for
  <filename>"}` (vuln-triage-mcp 0.1.0: both files). A filename PyPI does not know is a
  4,871-byte **HTML** 404 page, so the two can be told apart. With trusted publishing, both
  the wheel and the sdist had provenance (urllib3 2.8.0). A version can have many files
  (numpy 2.5.4: 66), so checking every file is not bounded.

### OSV severity labels

```
200 35372 B  POST https://api.osv.dev/v1/query  {"package":{"name":"requests","ecosystem":"PyPI"},"version":"2.19.0"}
200 39097 B  POST https://api.osv.dev/v1/query  {"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.0"}
```

- The label is `database_specific.severity` on GHSA records: `LOW`, `MODERATE`, `HIGH` and
  `CRITICAL` were all seen (lodash 4.17.0: 9 GHSA records, 1 `CRITICAL`, 4 `HIGH`, 4
  `MODERATE`; express 4.0.0 fixture: `MODERATE`, `LOW`).
- PYSEC records have no label: of 10 records for requests 2.19.0, the 5 `PYSEC-*` had no
  `database_specific.severity` (3 had only a `CVSS_V3` vector in `severity[]`, 2 had nothing).
- No record in these samples had a `withdrawn` key.
- lodash 4.17.0 returned 10 records (35,358 B) on 2026-11-02 and 9 (39,097 B) on 2026-11-04:
  OSV data changes between runs.

### OSV advisory ids

Measured 2026-11-04 with curl (`POST /v1/query`, body as above), for
`data/pk001_advisory_id_prefixes.yaml`:

```
200 35372 B    PyPI requests 2.19.0      10 records: GHSA 5, PYSEC 5
200 239175 B   PyPI django 3.2.0         66 records: GHSA 38, PYSEC 28
200 3983856 B  PyPI tensorflow 2.4.0    760 records: GHSA 382, PYSEC 378
200 730745 B   PyPI pillow 8.0.0        124 records: GHSA 68, PYSEC 56
200 85567 B    PyPI urllib3 1.24.1       26 records: GHSA 13, PYSEC 13
200 39097 B    npm lodash 4.17.0          9 records: GHSA 9
200 7584 B     npm express 4.0.0          3 records: GHSA 3
200 5243 B     npm minimist 1.2.0         2 records: GHSA 2
200 208384 B   npm axios 0.21.0          25 records: GHSA 25
```

- Record `id` prefixes seen: only `GHSA-` (545 of 1,025) and `PYSEC-` (480, PyPI only). Every id
  was an ASCII string matching `(GHSA|PYSEC)-[A-Za-z0-9._-]+`, at most 19 characters. Shapes:
  `GHSA-xxxx-xxxx-xxxx` (lowercase letters and digits) and `PYSEC-<year>-<1 to 4 digits>`.
- `aliases` held other prefixes (`CVE`, `BIT`, `SNYK`, `RUSTSEC`, `ASB`, and others), but none of
  them appeared as a record `id`, so none is in the PK001 allowlist. A record with any other id
  prefix still counts in PK001; only its id is left out of the evidence.
- `clients/osv.py` `parse_page` refuses a page whose records are not all objects with a string
  `id` (`ShapeMismatch`), since pagination de-duplicates by id.

## MCP client configs and package runners (read 2026-11-04)

For docs/rules-config.md (`scan_mcp_config`). Nothing here was fetched by the tool: it never
contacts a host. These are the pages the rules follow, read on 2026-11-04. Anything the pages do
not document is a skipped check (`not_determinable`), never a guess. The example servers on
these pages are not named here.

### Client config formats

| Client | Page | Server table | Per-server fields documented |
|---|---|---|---|
| Claude Code | https://code.claude.com/docs/en/mcp | `mcpServers` (top level of `.mcp.json` and of `~/.claude.json`), and `projects.<path>.mcpServers` in `~/.claude.json` (local scope) | `type`, `command`, `args`, `env`, `url`, `headers`, `headersHelper`, `timeout`, `alwaysLoad`, `oauth` (`clientId`, `callbackPort`, `authServerMetadataUrl`, `scopes`) |
| Claude Desktop | https://modelcontextprotocol.io/docs/develop/connect-local-servers | `mcpServers` in `claude_desktop_config.json` | `command`, `args`, `env` (remote servers are covered on a separate page and not configured in this file) |
| Cursor | https://cursor.com/docs/context/mcp | `mcpServers` in `.cursor/mcp.json` or `~/.cursor/mcp.json` | stdio: `type` (`"stdio"`), `command`, `args`, `env`, `envFile`; remote: `url`, `headers`, `auth` (`CLIENT_ID`, `CLIENT_SECRET`, `scopes`) |
| VS Code | https://code.visualstudio.com/docs/copilot/reference/mcp-configuration | `servers` in `mcp.json`; siblings `inputs` and `sandbox` are not servers. The portable format uses `mcpServers` in `.mcp.json` | stdio: `type`, `command`, `args`, `env` (strings, numbers or null), `envFile`, `cwd`, `dev`, `sandboxEnabled`, `sandbox`; http/sse: `type`, `url`, `headers`, `oauth` (`clientId`) |

`type` values:

- Claude Code: `stdio` (the default when `type` is absent), `http` (alias `streamable-http`),
  `sse` (deprecated), `ws`, and `sdk`, which Claude Code skips in files. "A JSON entry that has
  a `url` but no `type` is a configuration error, because Claude Code reads an entry with no
  `type` as a stdio server."
- VS Code: `stdio`, `http`, `sse`, all with `type` required. `url` also accepts `unix://`
  (Unix socket) and `pipe://` (named pipe).
- Cursor: `"stdio"` for local servers. The page gives no `type` for remote servers.

Variable syntax:

- Claude Code: `${VAR}` and `${VAR:-default}` in `command`, `args`, `env`, `url`, `headers`. An
  unset variable with no default stays as the literal `${VAR}` text. Plugin placeholders
  `${CLAUDE_PLUGIN_ROOT}`, `${CLAUDE_PLUGIN_DATA}`, `${CLAUDE_PROJECT_DIR}`.
- Cursor: `${env:NAME}`, `${userHome}`, `${workspaceFolder}`, `${workspaceFolderBasename}`,
  `${pathSeparator}`, `${/}` in `command`, `args`, `env`, `url`, `headers`.
- VS Code: `${input:id}` (prompted, VS Code format), `${env:NAME}`, `${workspaceFolder}`,
  `${userHome}`; the portable format uses `${NAME}` and `${NAME:-default}`. The page says to use
  the braced form: bare `$NAME` is literal text to VS Code.
- Claude Desktop: no variable syntax documented. The page's Windows note shows a literal
  `"..."` as an API key value in `env`.

Other points that affect the rules:

- Claude Code's `headersHelper` "executes ... as an arbitrary shell command" and merges its
  output into the request headers.
- Cursor's `envFile` and VS Code's `envFile` load environment variables from a file the config
  only names by path.
- VS Code keeps the OAuth client secret out of `mcp.json`. Cursor's `auth.CLIENT_SECRET` is in
  the file.
- The Claude Desktop guide's own example runs `npx -y <package>` with no version.

### Fields that run a command (re-read 2026-11-04)

Every server-config field the four pages say causes something to run:

| Client | Field | What the page says | CF004 |
|---|---|---|---|
| all four | `command` (+ `args`) | Claude Code: "Stdio servers run as local processes on your machine." VS Code: "Command to start the server executable." Cursor: the same wording | flagged only when it is a shell given an inline script; every stdio server has a `command`, so its presence alone is not a finding |
| Claude Code | `headersHelper` (string) | "Claude Code runs it when connecting and merges its output into the headers it sends." "Claude Code runs the command in a shell and gives up on it after 10 seconds." "Claude Code executes a `headersHelper` as an arbitrary shell command." It re-runs on each connection and after a 401/403, and in a project `.mcp.json` only after the folder is trusted | flagged on presence (`command_fields` in `config_shells.yaml`) |
| VS Code | `inputs[]` with `"type": "command"` (top level, not per server) | "runs a command and uses its result as the input value"; its `command` is "Command ID to run to obtain the input value" (example `myExtension.getApiKey`): an editor command ID, not a shell command | not flagged (see known-limits-config.md) |
| VS Code | `dev.watch` | "A glob pattern ... to watch for file changes that restart the MCP server": re-runs `command`, runs nothing new | not flagged |
| VS Code | `dev.debug` | "Enables you to set up a debugger with the MCP server" (Node.js and Python, stdio only); the page does not say what it launches | not flagged: undocumented |

Not running anything, per the pages: `envFile` ("Path to an environment file to load more
variables"), `cwd`, `env`, `sandboxEnabled`/`sandbox`, `oauth`, Cursor's `auth`, `url`,
`headers`. Cursor's page documents `command` as the only field that starts an executable, and the
Claude Desktop page documents only `command`, `args` and `env`. Claude Code's `apiKeyHelper`
appears on its MCP page only as a settings-file option, not an MCP server field, so it is out of
scope.

### Package runners: how a version is pinned

| Runner | Page | Package given by | Pinned | Not pinned |
|---|---|---|---|---|
| `npx` (`npm exec`) | https://docs.npmjs.com/cli/v11/commands/npx, https://docs.npmjs.com/cli/v11/using-npm/package-spec, https://docs.npmjs.com/cli/v11/configuring-npm/package-json (dependencies) | first positional argument, or `--package=<spec>` / `-p` (repeatable; the positional is then the command). `--` ends options. `-y`/`--yes` skips the prompt. `-c`/`--call` runs a shell string | `version`: "Must match `version` exactly". Version syntax is node-semver's ("Version must be parseable by node-semver") | no specifier ("matched with whatever version exists in the local project", otherwise fetched); `tag` ("A specific version tagged and published as `tag`"), so `latest`; ranges `>`, `>=`, `<`, `<=`, `~`, `^`, `1.2.x`, `*`, `""`, `a - b`, `a || b` |
| `pnpm dlx` (`pnpx`, `pnx`) | https://pnpm.io/cli/dlx | first positional, or `--package=<spec>` (repeatable) | "You may also specify which exact version of the package you'd like to use" (`pkg@<version>`) | no version. The page does not say which version is used then. `catalog:` takes the version from the workspace catalog, which is not in the config |
| `bunx` | https://bun.com/docs/pm/bunx | `bunx [flags] <package>[@version]`, or `--package`/`-p` | not stated. The page shows `@3.14.0` and `@2` but does not say either pins | no version (checks the registry for newer versions once a day) and `@latest` (checks on every run). Local installs are tried first |
| `uvx` (`uv tool run`) | https://docs.astral.sh/uv/guides/tools/, https://docs.astral.sh/uv/concepts/tools/ | first positional (the command, which names the package), or `--from <spec>` (the positional is then the command). `--with <spec>` adds packages and "supports package specifications" | `command@<version>` ("the `@` syntax cannot be used for anything other than an exact version"), `--from 'pkg==<version>'` | no version ("the latest available version ... on the first invocation", then the cached one), `@latest`, a range in `--from` (`'ruff>0.2.0,<0.3.0'`) |
| `pipx run` | https://pipx.pypa.io/latest/how-to/run-scripts.html | first positional ("a requirement specifier"), or `--spec <spec>` (the positional is then the app) | `pkg==<version>` | a range (`'esptool>=4.5'`). The page does not say which version is used with no specifier |

Non-registry sources, as the same pages document them:

- npm package-spec / package.json: a folder (`../`, `~/`, `./`, `/`), a tarball file or URL
  (`http://...`), git URLs (`git`, `git+ssh`, `git+http`, `git+https`, `git+file`, plus
  `git@host:...`), GitHub shorthand `user/repo` and `github:user/repo`, each with an optional
  `#ref`. An alias is `<alias>@npm:<name>`.
- uvx: `--from git+https://...`, with `@branch`, `@tag` or `@commit`.
- pipx: `git+https://...` (optionally `@branch`) and archive URLs given with `--spec`.

Not documented on the pages read, so the CF001 check on them is skipped (`not_determinable`):
the bunx version semantics, node-semver's loose forms (`v1.2.3`, `=1.2.3`), uv's `===`, a
requirement specifier as the uvx positional, `@` inside `--from`, pnpm's `catalog:`, and any
runner option not listed above (e.g. `uvx --python`). `yarn dlx`, `bun x`, `docker run` and
other runners are not checked.

### Shells (CF004)

| Shell | Page | Inline-script flags |
|---|---|---|
| `sh` and POSIX shells | https://pubs.opengroup.org/onlinepubs/9799919799/utilities/sh.html | `-c`: "Read commands from the command_string operand." |
| `cmd` | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd | `/c` "Carries out the command specified by `<string>` and then exits", `/k` (same, keeps running) |
| `pwsh` | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh | `-Command`/`-c`, `-CommandWithArgs`/`-cwa`, `-EncodedCommand`/`-e`/`-ec`. "All parameters are case-insensitive." |
| `powershell` (5.1) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe | `-Command`, `-EncodedCommand`. "All parameters are case-insensitive." `-`/`/` both accepted from `cmd.exe` |

`-File` runs a script file, not an inline script, and is not flagged. bash, zsh, dash, ksh and
fish are treated as POSIX `sh` for `-c` (their own manuals were not read; the flag is the same
in POSIX).

### Environment variables (CF007)

| Variable(s) | Page | What it does |
|---|---|---|
| `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` | https://man7.org/linux/man-pages/man8/ld.so.8.html | "A list of additional, user-specified, ELF shared objects to be loaded before all others." (LD_PRELOAD) |
| `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH` | https://man.cx/dyld(1) (a mirror of the macOS dyld(1) man page; no Apple-hosted copy was found) | "a colon separated list of dynamic libraries to load before the ones specified in the program" |
| `NODE_OPTIONS`, `NODE_PATH`, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_EXTRA_CA_CERTS` | https://nodejs.org/api/cli.html (Environment variables) | NODE_TLS_REJECT_UNAUTHORIZED: "If `value` equals `'0'`, certificate validation is disabled for TLS connections." |
| `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME` | https://docs.python.org/3/using/cmdline.html | PYTHONPATH: "Augment the default search path for module files." |
| `http_proxy`, `HTTPS_PROXY`, `ALL_PROXY` | https://curl.se/docs/manpage.html (ENVIRONMENT) | "The environment variables can be specified in lower case or upper case ... "http_proxy" is an exception as it is only available in lower case." Node reads `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` when `NODE_USE_ENV_PROXY` is set |

`PYTHONHTTPSVERIFY` is not on the Python page and is not listed. `NO_PROXY` only bypasses a
proxy and is not flagged.

## Response size reference

Largest bodies observed (uncompressed): registry page with limit=100, 190 KB; registry
single entry, 6.8 KB; PyPI project JSON, 3.87 MB (botocore, 2,545 releases); npm full
packument, 11.2 MB (@types/node); npm version document, under 7 KB.

### Per-version responses (measured 2026-11-02, uncompressed bytes)

| Request | Largest packages tried | Bytes |
|---|---|---|
| Registry `/v0/servers/{name}/versions/latest?include_deleted=true` | a third-party `io.github` entry (largest entry in the samples) | 8,529 |
| | `io.github.kimmawla/vuln-triage-mcp` | 701 |
| PyPI `/pypi/{p}/{v}/json` | numpy 2.5.4 | 63,184 |
| | torch 2.15.0 | 60,205 |
| | grpcio 1.85.1 | 56,782 |
| | pyarrow 26.0.0 | 46,586 |
| | opencv-python 5.0.0.93 | 28,765 |
| | tensorflow 2.21.0 | 18,280 |
| | boto3 1.43.123 / botocore 1.43.123 | 8,749 / 7,781 |
| PyPI `/integrity/.../provenance` | urllib3 2.8.0 wheel | 9,533 |
| npm `/{pkg}/latest` | aws-cdk-lib | 25,414 |
| | @modelcontextprotocol/sdk | 6,524 |
| | esbuild / typescript | 5,022 / 4,833 |
| | @aws-sdk/client-s3 / @types/node / @angular/core / next / react | 3,797 / 3,513 / 3,351 / 3,063 / 2,150 |
| npm `/-/npm/v1/attestations/{pkg}@{v}` | @modelcontextprotocol/sdk@1.32.2 | 15,167 |

For contrast, project-level documents: PyPI Simple JSON for botocore is 2,607,450 bytes (torch
620,970); the registry `/versions` list for the third-party server with 1,133 versions is
1,990,901 bytes.

The registry sizes above were measured on real responses for third-party entries, which are
not named here. Tests that need these sizes (`tests/test_http.py`) use invented `zqvex-*`
names with the same byte counts.

## Fixture index (`tests/fixtures/api/`)

| File | Request | Trimming |
|---|---|---|
| `registry_servers_search.json` | `/v0/servers?search=vuln-triage` | none |
| `registry_servers_page.json` | **synthetic**; shape of `/v0/servers?search=github&limit=3` (three third-party remote-only entries) | real capture in `local_fixtures/` |
| `registry_server_versions.json` | `/v0/servers/io.github.kimmawla%2Fvuln-triage-mcp/versions` | none |
| `registry_server_version.json` | `.../versions/latest` | none |
| `registry_server_version_deprecated.json` | **synthetic**; shape of `/v0/servers/{name}/versions/{v}` for a third-party deprecated entry | real capture in `local_fixtures/` |
| `registry_server_version_deleted.json` | **synthetic**; shape of `/v0/servers/{name}/versions/{v}?include_deleted=true` for a third-party deleted entry | real capture in `local_fixtures/` |
| `registry_servers_empty.json` | `/v0/servers?search=zzqqxx-no-such-server-2026` | none |
| `registry_server_not_found.json` | 404 for a missing server | none |
| `registry_endpoint_not_found.json` | 404 for `/v0/servers/{name}` | none |
| `registry_validation_error.json` | 422 for `limit=101` | none |
| `registry_bad_updated_since.json` | 400 for `updated_since=yesterday` | none |
| `pypi_project_self.json` | `/pypi/vuln-triage-mcp/json` | none |
| `pypi_project_requests.json` | `/pypi/requests/json` | removed `info.description`; `releases` kept only `2.34.2`, `2.32.3`, `0.0.1`; **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `pypi_release_requests_2.32.3.json` | `/pypi/requests/2.32.3/json` | removed `info.description`; **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `pypi_not_found.json` | 404 for a missing project | none |
| `pypi_simple_urllib3.json` | `/simple/urllib3/` (JSON) | kept last 3 `files` and last 3 `versions` |
| `pypi_simple_self.json` | `/simple/vuln-triage-mcp/` (JSON) | none |
| `pypi_provenance_urllib3.json` | `/integrity/urllib3/2.8.0/urllib3-2.8.0-py3-none-any.whl/provenance` | none |
| `pypi_provenance_not_found.json` | 404 provenance for requests 2.32.3 | none |
| `npm_packument_express.json` | `/express` | removed `readme`, `users`; `versions` and `time` kept only 5.3.0 (+ `created`, `modified`); **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `npm_packument_scoped_sdk.json` | `/@modelcontextprotocol%2fsdk` | as above, for 1.32.2; **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `npm_abbreviated_express.json` | `/express`, abbreviated | `versions` kept only 5.3.0 |
| `npm_abbreviated_esbuild.json` | `/esbuild`, abbreviated | `versions` kept only 0.28.2 |
| `npm_version_express_latest.json` | `/express/latest` | **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `npm_version_esbuild_latest.json` | `/esbuild/latest` | **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `npm_version_mcp_server.json` | **synthetic**; shape of `/{pkg}/{version}` for a third-party MCP server package with `mcpName` | real capture in `local_fixtures/` |
| `npm_not_found.json` | 404 for a missing package | none |
| `osv_query_express_4.0.0.json` | `POST /v1/query` npm express 4.0.0 | none |
| `osv_query_empty.json` | `POST /v1/query` six 1.17.0 (`{}`) | none |
| `osv_query_invalid_cursor.json` | `POST /v1/query` with a made-up `page_token` (400) | none |
| `npm_version_not_found.json` | `/express/0.0.0-no-such-version` (404) | none |
| `npm_version_package_not_found.json` | `/no-such-package-zzqq-2026/1.0.0` (404) | none |
| `pypi_release_zero_files.json` | `/pypi/requests/0.0.1/json` (no files) | removed `info.description`; **pseudonymized** (personal values invented, real capture in `local_fixtures/`) |
| `pypi_release_self_0.1.0.json` | `/pypi/vuln-triage-mcp/0.1.0/json` | none |

### Synthetic package fixtures (`tests/fixtures/package/`)

All **synthetic**, for the audit_package tests. Each keeps the keys and nesting of the real
response named here; values are invented (`zqvex-*` names, `@example.invalid` addresses,
made-up digests, ids and signatures, inert certificate text) except vuln-triage-mcp's own
provenance 404 body.

| File | Shape of |
|---|---|
| `pypi_release_zqvex.json` | `/pypi/{p}/{v}/json` (`pypi_release_self_0.1.0.json`), two files |
| `pypi_project_zqvex.json` | `/pypi/{p}/json` (`pypi_project_self.json`) |
| `pypi_provenance_zqvex.json` | `/integrity/.../provenance` 200 (`pypi_provenance_urllib3.json`) |
| `pypi_provenance_none_zqvex.json` | `/integrity/.../provenance` JSON 404 (no provenance) |
| `pypi_provenance_self_whl_404.json` | the real JSON 404 for vuln-triage-mcp 0.1.0's wheel (80 B, above) |
| `pypi_provenance_self_sdist_404.json` | the real JSON 404 for vuln-triage-mcp 0.1.0's sdist (70 B, above) |
| `npm_version_zqvex.json` | `/{pkg}/{version}` with `dist.attestations` (`npm_version_express_latest.json`) |
| `osv_query_zqvex.json` | `POST /v1/query` with GHSA and PYSEC-style records (`osv_query_express_4.0.0.json`) |

### Personal data in fixtures

Personal values never appear in a committed fixture. In the seven **pseudonymized** files,
every value inside npm `maintainers`, `contributors`, `author` and `_npmUser` (including
`approver` and `trustedPublisher`), and PyPI `info.author`, `author_email`, `maintainer`,
`maintainer_email` and `ownership.roles[].user`, was replaced with an invented one:
`zqvex-person-N` for names and logins, `zqvex-user-N@example.invalid` for addresses (one N per
person across all files, so a maintainer listed twice keeps one pseudonym, and a
`Name <address>` pair shares its N), `https://zqvex-person-N.example.invalid` for an author
URL, and `zqvex-ci-publisher`, `zqvex-ci-publisher@example.invalid`, `zqvex-ci` and
`oidc:zqvex-oidc-config-N` for npm's trusted-publishing service identity. Every key, nesting
level, array length and JSON type is unchanged, and nothing was shrunk or removed: these
fixtures were already trimmed as the index says, and the large-response sizes that
`tests/test_http.py` relies on are recorded above, not carried by the fixtures. Other values
(versions, repository URLs, digests, dates) are the real ones. Synthetic fixtures use the same
`@example.invalid` addresses.

`tests/test_no_personal_data.py` enforces this: no email address in tracked files under
`tests/`, `docs/`, `scripts/` and `src/` (except `src/mcp_supply_audit/data/`), `README.md` or
`SECURITY.md` beyond `@example.invalid`, GitHub no-reply addresses and a reviewed allowlist;
nothing under `local_fixtures/` tracked by git; and only invented `zqvex` values inside any
`_npmUser`, `maintainers` or `author_email` block of a tracked fixture.

Third-party fixture content (descriptions, READMEs, status messages) is untrusted; tests must
treat it as data. Tests and docs use invented `zqvex-*` names, never real third-party registry
names (`tests/test_no_real_names.py`).
