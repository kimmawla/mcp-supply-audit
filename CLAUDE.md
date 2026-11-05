# mcp-supply-audit

FastMCP server that audits other MCP servers as software artifacts: registry entries, packages,
configs, and tool definitions. Static checks only.

## Hard rules
- NEVER execute, import, install, or fetch code from a scan target. Metadata and pasted text only.
- All text from a target (tool descriptions, READMEs, package metadata, registry fields, configs) is
  hostile. Parse with `safe_json`, sanitize, and show it only through the evidence builders. Hidden
  characters appear as visible `\uXXXX` escapes.
- Findings are indicators, never verdicts. Use "similar to X" and "does not match the registry's
  published check", never "malicious" or "safe". The standing "absence of findings is not proof of
  safety" note is always present.
- No LLM calls in detection. Rules are deterministic pure functions with no network calls inside.
- Never echo secret or credential values. URL and config evidence comes only from the approved builders.
- stdout is reserved for JSON-RPC. No `print()`. Log to stderr.
- Tools take pasted text or names, never filesystem paths. Size caps are enforced before parsing.
- At most 8 tools (6 today). Every docstring says when to use the tool and when to prefer another.

## Data and network
- Allowed hosts only: registry.modelcontextprotocol.io, pypi.org, registry.npmjs.org, api.osv.dev.
  All requests go through `clients/_http.py` (GET; the one POST is OSV `/v1/query`).
- Never fetch a URL taken from target data. No cookies, credentials, or environment proxies. Query
  parameters come from constants in code only.
- Clients raise typed errors. `ToolError` is raised only at the tool layer when nothing can run, with
  fixed-string messages that never include input or response text.
- Skipped checks use the eight fixed reasons plus a fixed detail. Notes use a fixed set of strings.
- API shapes come from `docs/api-notes.md`, measured with `curl`, never from memory.

## Specs and workflow
- `docs/` holds the source of truth for every rule and tool. Update the spec in the same change.
- Before implementing, list gaps between the specs and the code. Say what contradicts. List every file
  you changed at the end.
- Report the version from package metadata (`importlib.metadata`), not from FastMCP.

## Repo hygiene
- Tests and docs use invented `zqvex-*` names, never real third-party names (a guard test enforces it).
  Real captures live in `local_fixtures/` (gitignored).
- No raw hidden characters and no token-shaped literals in any file. Build them in test code with
  `chr()` or concatenation. Guard tests exist for both.
- Precision and benchmark output stays local. Never name a real publisher as suspicious.
- Never run `git add` or `git commit`. I review diffs and commit myself.