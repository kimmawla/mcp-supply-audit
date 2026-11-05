# mcp-supply-audit

<!-- mcp-name: io.github.kimmawla/mcp-supply-audit -->

> Audits MCP servers as software artifacts: registry entries, packages, configs, tool definitions.

An MCP server. Static checks only. It never runs the code it inspects.

**Status: pre-release, in development.** Not yet published. Nothing here is a security guarantee.

## Why this exists
Most MCP security scanners focus on tool descriptions. This project looks at the server as a
supply-chain artifact: does the registry entry match its package and repo, is the name close to a
popular one, what do the package version's own metadata and advisories say, and what does the
config you are about to copy actually do.

## What works today
Six tools, served over stdio by a FastMCP server ([tool surface](docs/tool-surface.md)). All are
read-only and take names or pasted text, never a path.

- `audit_server`: runs the checks below that apply to one server (a registry name, or a package
  name plus `pypi`/`npm`) concurrently under a 30 s deadline, and returns one merged report. A check
  that fails or times out is listed as skipped; the rest of the report still returns.
- `audit_registry_entry`: an MCP Registry entry's repository consistency with its packages, owner
  match, package and version existence, ownership markers, status, and remote URLs (as text).
- `audit_package`: one PyPI or npm package version's OSV.dev advisories, yanked or deprecated
  state, install scripts (npm only), provenance, publish recency (PyPI only) and declared repository.
- `check_typosquat`: whether a name is close to one in a dated reference list (curated PyPI and
  npm names; for registry names, also names crawled from the MCP Registry).
- `scan_mcp_config`: an MCP client config's servers, for unpinned runners, plain-http remotes,
  hardcoded secrets, shell wrappers, broad paths, non-registry sources and risky env.
- `scan_tool_definitions`: checks a `tools/list` snapshot for hidden Unicode, instruction-like
  phrasing, cross-tool references, exfiltration phrasing, encoded blobs, and other indicators.

Outbound requests go only to registry.modelcontextprotocol.io, pypi.org, registry.npmjs.org and
api.osv.dev.

## Quick start
Not on PyPI yet: these commands work once the package is published. Until then, run it
[from a source checkout](#from-a-source-checkout).

For Claude Code, with [uv](https://docs.astral.sh/uv/):

```bash
claude mcp add mcp-supply-audit -- uvx mcp-supply-audit
```

Pinned to one version (uvx's `package@version` form):

```bash
claude mcp add mcp-supply-audit -- uvx mcp-supply-audit@0.1.0
```

`scan_mcp_config` flags the first form in the configs it scans (CF001, unpinned package runner).

### From a source checkout
Run it from a checkout of this repository with [uv](https://docs.astral.sh/uv/):

```bash
cd mcp-supply-audit
uv sync
```

Then point an MCP client at the `mcp-supply-audit` console script in that checkout. For Claude
Code:

```bash
claude mcp add mcp-supply-audit -- uv --directory /path/to/mcp-supply-audit run mcp-supply-audit
```

For clients configured with JSON (e.g. Claude Desktop's `mcpServers`):

```json
{
  "mcpServers": {
    "mcp-supply-audit": {
      "command": "uv",
      "args": ["--directory", "/path/to/mcp-supply-audit", "run", "mcp-supply-audit"]
    }
  }
}
```

Then ask, for example, "Is the MCP server `<namespace>/<name>` safe to install?" and the client
can call `audit_server`. Read the report's skipped checks: a report with no findings is not proof
of safety.

## Design principles
- **Never executes a scan target.** Static analysis and metadata only. No tool accepts a filesystem path.
- **Hostile input by default.** Text from a target is sanitized, capped, and returned only as quoted
  evidence under `untrusted_text`. Hidden characters are shown as visible `\uXXXX` escapes.
- **Deterministic rules, no LLM in detection.** Results are reproducible and unit-tested.
- **Findings are indicators, not verdicts.** Every report lists which checks ran and which were
  skipped, and states that no findings is not proof of safety.
- **Mapped to the OWASP MCP Top 10** (beta, v0.1), by ID.

## Limits
Static checks cannot see runtime behavior. Audit and telemetry gaps, shadow servers, and context
over-sharing are outside what this tool can detect.

Per-check limits: [registry checks](docs/known-limits-registry.md),
[package checks](docs/rules-package.md#known-limits),
[typosquat checks](docs/rules-typosquat.md#known-limits-quoted-by-the-readme),
[config checks](docs/known-limits-config.md).

## Evaluation
No benchmark has been run yet.

## Development
```bash
uv sync
uv run pytest -q
uv run ruff check
uv run ruff format --check
```

## Security
To report a vulnerability in this project, see [SECURITY.md](SECURITY.md).

## License
MIT