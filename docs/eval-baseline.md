# Tool-definition eval baseline

Measured before any rule change.

- Date: 2026-11-09
- Code: commit 47f5543 plus the uncommitted working tree of that day; no rule or rule-data
  change in it.
- Command: `uv run scripts/eval_tool_defs.py --committed-only` (no local benign snapshots
  existed, so the full run gives the same numbers).
- Counts only. Definitions are in `docs/rules-tool-definitions.md` (Evaluation corpus).

## Positives

| Count | Value |
|---|---|
| Patterns in the manifest | 25 |
| Counted (scope static, source fetched) | 19 |
| Not counted, scope outside | 4 |
| Not counted, static from an unfetched source | 2 |
| At least one expected rule fired | 12/19 |
| Exact match (fired equals expected) | 6/19 |
| Extra rules fired | 0/19 |

## Mutations

134 mutants generated: 125 from counted patterns, 9 not counted. Two mutation-artifact
cells are excluded from the rates; neither fired.

Detected/total per rule and mutation type, over counted patterns, artifacts excluded.
"-" means no mutant of that type expects the rule.

| Rule | case | whitespace runs | whitespace in words | split fields | synonym | param move | homoglyph |
|---|---|---|---|---|---|---|---|
| TD001 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| TD002 | 3/14 | 3/14 | 0/14 | 2/14 | 1/14 | 2/13 | 1/14 |
| TD003 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| TD004 | 2/8 | 2/8 | 2/8 | 2/8 | 2/8 | 2/7 | 0/8 |
| TD005 | - | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 |
| TD006 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| TD007 | 3/3 | 2/2 | 3/3 | 2/2 | 3/3 | 1/1 | 2/3 |
| TD008 | 1/1 | - | - | - | - | - | 0/1 |

## Benign

0 snapshots (0 committed, 0 local), 0 tools, 0 unscannable, 0 findings for every rule.
No benign false-positive rate exists yet.

## Registry-tier typosquat flags: hand-review tally

Measured before any rule change.

- Pairs reviewed: 51 (rule TS006: 50, rule TS003: 1)
- Plausible lookalike: 25
- Legitimately distinct: 10
- Unclear from names alone: 16
- Precision range: 25/51 (about 49%) counting unclear as a miss, 25/35 (about 71%) excluding unclear, 41/51 (about 80%) counting unclear as a hit

Limits: single reviewer, who is also the rule author. Judged from names only, with no publisher or adoption context. Registry tier only. Precision only, with no recall measurement. TS003 has one pair, so no rate is given for it.
