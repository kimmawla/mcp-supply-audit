# mcp-supply-audit

<!-- mcp-name: io.github.kimmawla/mcp-supply-audit -->

> Audits MCP servers as software artifacts: registry entries, packages, configs, tool definitions.

An MCP server. Static checks only. It never runs the code it inspects.

**Status: pre-release, in development.** Not yet published. Nothing here is a security guarantee.

## Quick start
Check an MCP server's registry entry, package, config and tool definitions before you install it.

For Claude Code, with [uv](https://docs.astral.sh/uv/):

```bash
claude mcp add mcp-supply-audit -- uvx mcp-supply-audit
```

To pin one version, use `uvx mcp-supply-audit@0.1.1` instead. `scan_mcp_config` flags the
unpinned form in the configs it scans (CF001).

For Claude Desktop, add this to `mcpServers` in its config file:

```json
{
  "mcpServers": {
    "mcp-supply-audit": {
      "command": "uvx",
      "args": ["mcp-supply-audit"]
    }
  }
}
```

Then paste a prompt like one of these:

- "Audit the MCP server `<namespace>/<name>` before I install it."
- "Scan this MCP config:" followed by your config's JSON.
- "Check the npm package `<name>` for advisories and install scripts."

**Privacy.** Every tool takes pasted text or names, never a file path. A config scan's report
shows no env, header or argument values and no URL paths or queries. It shows server names,
key names, argument positions, and only the scheme, host and port of a URL. Text you paste still
goes to your MCP client and its model like any other message, so remove real secrets first.

Sample: a config scan of four invented servers, with an unpinned `npx` package, a plain-http
URL, a literal API key in `env` plus a `/` path argument, and `bash -c`. The output is from
`scripts/demo.py`'s summary format, with the coverage lists trimmed:

```text
Severity counts: critical 0, high 3, medium 2, low 0, info 0
Assessment: findings_present

Findings (5):
  [high] CF002: Remote server URL does not use https
      at servers[1].url
  [high] CF003: Credential-named env entry holds a literal value
      at servers[2].env
  [high] CF004: Server starts through a shell (sh) with an inline script
      at servers[3].args[0]
  [medium] CF001: Package runner (npx) runs a package with no version, not an exact version
      at servers[0].args[1]
  [medium] CF005: Path argument grants a filesystem root
      at servers[2].args[2]

Checks that ran (16):
  CF001:servers[0]
  ...
Skipped checks (12):
  CF002:servers[0]: not_applicable
  ...
Notes:
  - Servers scanned: 4. Servers skipped: 0.
  - Absence of findings is not proof of safety. Only static checks were run; see coverage for which checks ran and which were skipped.
```

Findings are indicators for review, not verdicts. Read the skipped checks too.

### From a source checkout
Run `uv sync` in a checkout of this repository, then point the client at it:

```bash
claude mcp add mcp-supply-audit -- uv --directory /path/to/mcp-supply-audit run mcp-supply-audit
```

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
Counts from [docs/eval-baseline.md](docs/eval-baseline.md), measured 2026-11-09, for the
tool-definition rules TD001 to TD008 only. Findings are indicators for review, not verdicts, and
no findings is not proof of safety.

**What was measured.** Static detection on 19 positives (in scope for one `tools/list` snapshot,
from sources that were fetched and read), 125 mutants of them, and a benign corpus of 9 servers
with 77 tools. Two runs: a baseline before any rule change, and a run after tuning TD002 to TD004
on the same fixtures, which is in-sample.

| | Baseline | After tuning (in-sample) |
|---|---|---|
| At least one expected rule fired | 12/19 | 19/19 |
| Exact match (fired equals expected) | 6/19 | 15/15 (15/19 over every counted pattern) |
| Extra rules fired | 0/19 | 0/19 |
| Benign findings | no benign corpus yet | 0, on 9 servers and 77 tools |

The 15/15 is partly by construction: four TD004 expectations were declared outside that rule's
documented scope and left out of the denominator, and they are exactly the four non-matches.

**Known evasions** (after tuning, mutants detected). Look-alike letters: TD002 1/14, TD003 0/5,
TD004 0/4. Words split by a space: TD002 6/14, TD003 1/5, TD004 2/4.

**Typosquat (registry tier).** 51 flagged pairs, hand-reviewed: 25 plausible lookalikes, 10
legitimately distinct, 16 unclear. Precision is 49% to 80% depending on how unclear pairs count
(71% excluding them). Recall was not measured. One reviewer, who wrote the rules, judged from
names only.

**Limits.**
- The positive fixtures are model-written paraphrases, written by a model that had read the
  rules, so they may match the rules' wording more closely than real attacks do.
- The post-tuning numbers are in-sample. The baseline is the out-of-sample reference.
- 66 of the 77 benign tools come from one publisher's reference servers, and none are email,
  chat or secrets tools. The rest come from the author's own two servers, which were also
  development negatives. Zero benign findings is not a false-positive rate for other servers.
- A held-out evaluation is pending: the script exists, the corpus is not collected yet.

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