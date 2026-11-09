# Tool-definition rules (input: a tools/list JSON snapshot)

| Rule | Detects | Severity | Confidence |
|---|---|---|---|
| TD001 | Hidden Unicode: zero-width, bidi controls, tag characters in name/description/params | high | high |
| TD002 | Instruction-like phrasing aimed at the model ("ignore previous", "do not tell the user", "before using this tool...") | high | medium |
| TD003 | Description references other tools or servers by name | medium | medium |
| TD004 | URLs or "send/post to" exfil phrasing in a description or title (tool `title`, `annotations.title`, and schema `description`/`title` at any depth) | medium | medium |
| TD005 | Long encoded blobs (base64/hex runs) | medium | medium |
| TD006 | Excessive description length (threshold in config) | low | high |
| TD007 | Free-text parameters whose names invite conversation content ("notes", "context", "sidenote") | low | low |
| TD008 | Duplicate tool names within one snapshot | medium | high |

Each rule: pure function, one fixture file of positives (`tests/fixtures/tool_defs/suspicious/`).
The benign negatives are shared across rules: every rule runs on every file in
`tests/fixtures/tool_defs/benign/` and on the benign eval corpus below, and the results are
counted per rule (findings, and snapshots with at least one finding).
Phrase lists live in data files, not code, so they can be reviewed and versioned.

## Evaluation corpus

Separate from the per-rule fixtures above. It measures the rules and is never used to tune them.

- Positives: `tests/fixtures/eval/positives/`, one inert fixture per pattern from public
  research. `tests/fixtures/eval/MANIFEST.yaml` holds each pattern's source URL, a one-line
  description, the rule ids the spec expects (set before scanning; `[]` with
  `scope: outside` when one snapshot cannot show the pattern) and the key phrase that
  mutations target.
- Mutations: `scripts/eval_mutations.py`, generated in memory and never committed. Types:
  case, whitespace runs, whitespace inside words, split across description and title,
  synonym (fixed list), moved into a parameter description, Cyrillic homoglyphs.
- Benign: real `tools/list` snapshots collected by hand in a locked-down container, as set out
  in `docs/benign-corpus.md`.
- Report: `uv run scripts/eval_tool_defs.py`. It is offline and deterministic, and its output
  stays local.
- Denominators: positive counts (at least one expected rule fired, exact match, extra rules
  fired) are taken over the counted patterns only: `scope: static` and a source with
  `fetched: true`. Patterns with `scope: outside` and static patterns from an unfetched source
  are listed by id and left out of every count, including the mutation rates.
- Mutation artifacts: a (pattern, mutation, rule) cell where the mutation removes what the
  rule looks for is listed in `MUTATION_ARTIFACTS` in the report script, left out of the rates
  and shown separately. Two today: upper-casing a base64 blob (p20, case, TD005) and the
  synonym list renaming a duplicated tool name (p18, synonym, TD008).
- Baseline: `docs/eval-baseline.md` records the counts measured before any rule change.

## Known gaps

Recorded so the evaluation is read against what the rules can see today. Not yet addressed.

- Field walk (all rules): the scanned strings are the tool `name`, `title`, `description` and
  `annotations.title`, and in `inputSchema`/`outputSchema` at any depth: `description`,
  `title`, property names, `$defs`/`definitions`/`patternProperties` keys, and the values
  and keys under `enum`, `default`, `const` and `examples`. Nothing else is read: not
  `required` entries, `$comment`, `pattern`, `format`, `$ref`, `type`, `_meta`, or
  annotations other than `title`.
- TD002 skips name fields: it checks descriptions, titles and schema values (and their keys)
  but not tool names, parameter names or schema keys. With the field walk above, an
  instruction written as a parameter name or as a `required` entry is not seen.
- TD003 finds a tool reference by name only when the name is snake_case (at least one `_`)
  followed by "tool", or quoted (backticks, single or double quotes) before "tool", or follows
  "tool named"/"tool called" (quoted, or with a `_`, `.` or `-` separator). An unquoted
  kebab-case or single-word name ("the zqvex-send tool", "the messenger tool") is not
  matched; only the phrase list in `td003_cross_references.yaml` can catch those.
