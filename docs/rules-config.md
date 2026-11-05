# Config rules (source of truth)

Tool: `scan_mcp_config(config_text)`. Input: the text of an MCP client config (JSON). No network access
and no filesystem access: the tool takes pasted text, never a path.

Config formats and runner pinning syntax follow each client's and runner's own documentation, read
2026-11-04 and cited by URL in docs/api-notes.md ("MCP client configs and package runners"). Anything
not documented there is a skipped check, never a guess.

Implemented in `config_scan.py` and `detectors/config_rules.py`; served by `server.py`.

## Input handling
- Size cap 256 KiB, depth limit 64, parsed with `safe_json`. Not JSON, too large, too deep, or not a
  JSON object -> short ToolError with fixed wording.
- Server tables: `mcpServers` (Claude Code, Claude Desktop, Cursor, VS Code's portable format),
  `servers` (VS Code), and `projects.<path>.mcpServers` (Claude Code's `~/.claude.json`). VS Code's
  `inputs` and `sandbox` are documented and are not servers. No server table -> ToolError (nothing
  can run). A server table that is not an object -> ToolError.
- Servers are numbered across all tables in order (`servers[0]`, `servers[1]`, ...).
  Up to 200 servers, 100 args per server, 4096 characters per string. A server over a limit is skipped
  with `shape_mismatch` and detail `server over a size limit` (or `server entry malformed` for a
  non-object or a field of the wrong type), and the others still run. Servers after the first 200 are
  one skipped check per rule with detail `too many servers`.
- Per server: `command`, `args`, `env`, `url`, `headers`, `type`, and Cursor's `auth` (string fields).
  `env` values may be strings, numbers or null (VS Code). Other documented fields (`envFile`, `cwd`,
  `headersHelper`, `timeout`, `alwaysLoad`, `oauth`, `dev`, `sandboxEnabled`, `sandbox`) are accepted;
  only `headersHelper` is checked, and only for presence (CF004). Unknown fields, and unrecognized top-level keys, are ignored and counted in the
  report's `notes` (the `Coverage` type has no counts).
- The config may contain real secrets. Values are NEVER echoed. Findings name the server by index
  (location) plus a sanitized name (evidence), and the key or argument position, never the value.
  The config text is never logged; a rule crash logs only the exception type.

## Placeholders
A value is a placeholder, not a secret, when nothing literal is left after removing variables
(`${VAR}`, `${env:NAME}`, `${input:id}`, `${userHome}`, ...), `<...>` placeholders, and a leading
`Bearer`/`Basic`/`Token` word, i.e. no letter or digit remains ("Bearer ${TOKEN}", "<your-key>", "...",
""). In `${VAR:-default}` (Claude Code, VS Code portable) the default is literal text and is checked.

## Rules
| Rule | Detects | Severity | Confidence |
|---|---|---|---|
| CF001 | Package runner (`config_runners.yaml`: npx, npm exec, pnpm dlx/pnpx/pnx, bunx, uvx, uv tool run, pipx run) running a package without an exact version pin (none, `latest`, a range, a tag) | medium | high |
| CF002 | Remote `url` whose scheme is not https or wss, other than loopback (`localhost`, `127.x.x.x`, `[::1]`) and VS Code's local `unix://` and `pipe://` | high | high |
| CF003 | Credential-looking value in `env`, `headers`, `auth`, args, or URL userinfo/query/path, by key name (`rg011_credential_params.yaml`) or by value shape (`secrets.py`). Placeholders don't count | high | medium |
| CF004 | Shell wrapper: `command` is a shell (`config_shells.yaml`) given an inline-script flag (`-c`, `/c`, `/k`, `-Command`, `-EncodedCommand`, ...); a second finding when that script pipes a download into an interpreter. Also the presence of a field the client runs as a shell command (`command_fields` in `config_shells.yaml`: Claude Code's `headersHelper`) | high | medium (field presence: high) |
| CF005 | Broad filesystem scope: a path argument (or `--flag=value`) that is a root, a home directory, or a drive root | medium | low |
| CF006 | Package source that isn't a registry name: git URL, tarball/archive URL, or local path given to a runner as the package | medium | medium |
| CF007 | `env` entry that weakens or redirects the runtime (`config_env_risky.yaml`): loader injection, `NODE_OPTIONS`, `PYTHONPATH`, `PATH`, proxy variables, disabled TLS verification | high | high |

Rule details:
- CF001/CF006: "Pinned" means whatever the runner's own docs say pins a version (docs/api-notes.md):
  an exact semver version for npm-style runners, `pkg@<version>` for uvx (`@` is exact-only),
  `==<version>` (no `*`) in a requirement for uvx `--from`/`--with` and pipx. A `latest` tag is never
  a pin. An undocumented option or version form (bunx versions other than none/`latest`, `v1.2.3`,
  `===`, pnpm `catalog:`, `uvx --python`, ...) is `not_determinable` with detail
  `runner syntax not documented`; a `${...}` package spec has detail `value is a placeholder`. When a
  server has both an unpinned and an undeterminable package, the finding is reported and the check
  counts as run.
- CF002: a `${...}` scheme or host (e.g. `${BASE_URL:-https://...}/mcp`) is `not_determinable`
  with detail `value is a placeholder`.
- CF003 key names: for `env`, `headers`, `auth` and `--flag` arguments, a listed name matches as the
  whole key or as its last `_`/`-`-separated part (`ZQVEX_API_KEY`, `X-Auth-Token`, `--auth-token`).
  URL query parameters keep RG011's whole-name rule, so `page_token` is not a credential. A
  credential-named flag's value is the text after `=` or the next argument if it is not a flag.
- CF004: running a script file (`bash start.sh`, `pwsh -File start.ps1`) is not flagged. A
  command field (`headersHelper`) is flagged when present with any non-null value, whatever its
  type; the value is never read. Its evidence is the field name and the server index, then the
  sanitized server name (`field headersHelper; servers[2]; server <name>`), and its location is
  `servers[i].headersHelper`. The inventory of command-running fields is in docs/api-notes.md
  ("Fields that run a command").
- CF007: an entry with `values` (e.g. `NODE_TLS_REJECT_UNAUTHORIZED: 0`) is flagged only for those
  values; others are flagged for any value except a pass-through of the same variable
  (`PATH: ${PATH}`).

## OWASP MCP Top 10 mapping
Ids are the exact ones in src/mcp_supply_audit/owasp.py; `RULE_OWASP` in
detectors/config_rules.py must match this table (tests compare them).

| Rule | OWASP id | Rationale |
|---|---|---|
| CF001 | MCP04:2025 | An unpinned runner installs whatever version is newest at start-up, so a hijacked release runs without review. |
| CF002 | MCP01:2025 | A plain-http remote sends tokens and tool traffic where they can be read in transit. |
| CF003 | MCP01:2025 | A secret written into the config leaks to anyone who can read, share, or commit the file. |
| CF004 | MCP05:2025 | A shell parses the start-up string, so the config runs arbitrary commands, including downloaded code. |
| CF005 | MCP02:2025 | A root or home directory grants the server far more of the filesystem than its task needs. |
| CF006 | MCP04:2025 | A git, tarball, or local source bypasses the registry and its versioning, so what runs is unreviewed. |
| CF007 execution | MCP05:2025 | Loader and module-path variables make the runtime load code the server's package does not contain. |
| CF007 transport | MCP01:2025 | Proxy and TLS variables send traffic, and the credentials in it, through a party or check that can be bypassed. |

## Behavior
- Rules are pure functions over a normalized server (`config_rules.Server`). No network calls.
- Typed errors only. Skipped checks use the eight fixed reasons with a detail.
- A rule that raises is a skipped check with `rule_error`; a malformed rule data file is
  `shape_mismatch`, a missing one `not_determinable`.
- The report states how many servers were scanned and how many skipped (`notes`), plus the standing note.
- Evidence: fixed phrases, key names, and argument positions only. Never values, URL paths or queries, or
  environment values. URL evidence reuses the minimal scheme/host/port builder (`url_evidence`).
  `config_evidence` is the only other builder, and a static test checks that every CF rule passes
  evidence from it. Server and key names are capped at 40 characters and pass through `scrub`, so a
  secret-shaped name is shown as `<redacted>`.

## Not implemented in v0.1
- What a pinned package does, or whether its version is vulnerable (use `audit_package`).
- Client permission or approval settings.
- Reading config files from disk, including files named by `envFile`.
- Known limits: docs/known-limits-config.md.
