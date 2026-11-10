# Changelog

Findings are indicators for review, not verdicts. No findings is not proof of safety.

## 0.1.1 - unreleased

### Changed
- **Wider tool-definition coverage.** TD002 (instruction-like phrasing), TD003 (cross-references
  to other tools or servers) and TD004 (exfiltration-like phrasing) match more phrasings. Their
  phrase lists in `src/mcp_supply_audit/data/` grew, and the detectors in `detectors/tool_defs.py`
  changed to match.
- **More string fields scanned.** All tool-definition rules now read one shared field walk:
  tool name, title, description, every string under `annotations` (keys included), and, at any
  depth of `inputSchema` and `outputSchema`, descriptions, titles, property names, schema keys,
  `enum`/`default`/`const`/`examples` values and keys, and `required` entries. TD001 and TD002
  check every kind in the walk. `$comment`, `pattern`, `format`, `$ref`, `type`, `_meta` and
  unknown keywords are still not read. See
  [docs/rules-tool-definitions.md](docs/rules-tool-definitions.md#fields-scanned).

### Added
- **Evaluation corpus and docs.** 25 positive fixtures (19 in scope for one `tools/list` snapshot), a benign
  corpus manifest, mutation and held-out evaluation scripts, and a baseline report
  ([docs/eval-baseline.md](docs/eval-baseline.md), [docs/benign-corpus.md](docs/benign-corpus.md)).
  The post-tuning numbers are in-sample. The held-out corpus is not collected yet.
- **Documented evasion limits.** The README and
  [docs/rules-tool-definitions.md](docs/rules-tool-definitions.md) list mutants that still
  get past TD002 to TD004, such as look-alike letters and words split by a space, with counts.

## 0.1.0

- First release.
