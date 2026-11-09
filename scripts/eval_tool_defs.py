"""Evaluation report for TD001-TD008: research positives, their mutations, benign snapshots.

Dev-only: run by hand. Never imported by src/. Offline and deterministic: reads committed
fixtures and local files only, sends no requests, uses no randomness. Prints to stderr and
writes nothing. The numbers are for local review (CLAUDE.md: benchmark output stays local).

Inputs
  tests/fixtures/eval/MANIFEST.yaml and positives/*.json   positives and expected rule ids
  scripts/eval_mutations.py                                mutants, generated in memory
  tests/fixtures/eval/benign/*.json                        committed benign snapshots
  local_fixtures/benign/*.json                             local benign snapshots (gitignored)

Sections
  1. Per pattern: expected rule ids, fired rule ids, missing and extra. Then the counts over
     the counted patterns only: scope static and a source with fetched: true. Patterns with
     scope outside, and static patterns whose source has fetched: false, are listed by id
     and left out of every count.
  2. Per rule and mutation type: detection rate, as fired/total over the mutants of counted
     patterns whose pattern expects that rule. "-" when no such mutant exists. The cells in
     MUTATION_ARTIFACTS are left out of the rates and listed after the table.
  3. Benign: per rule, the number of findings and of snapshots with at least one finding.
     Counts only: no evidence text, no server or tool names, no file names.

Every snapshot goes through scan_tool_definitions, the same entry point the tool uses.

Usage: uv run scripts/eval_tool_defs.py [--committed-only]
  --committed-only  skip local_fixtures/benign/ (used by the tests)
Exit status: 0 printed, 1 manifest or fixture unreadable.
"""

import argparse
import importlib.util
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastmcp.exceptions import ToolError

from mcp_supply_audit.detectors.tool_defs import RULES, scan_tool_definitions

ROOT = Path(__file__).resolve().parents[1]
COMMITTED_BENIGN = ROOT / "tests/fixtures/eval/benign"
LOCAL_BENIGN = ROOT / "local_fixtures/benign"
RULE_IDS = tuple(rule_id for rule_id, _ in RULES)

# (pattern, mutation, rule) cells where the mutation removes the thing the rule looks for,
# so a miss says nothing about the rule. Left out of the detection rates, shown separately.
MUTATION_ARTIFACTS: frozenset[tuple[str, str, str]] = frozenset(
    {
        # Upper-casing the field also upper-cases the base64 blob, so it no longer
        # decodes to the same bytes.
        ("p20_encoded_instruction", "case", "TD005"),
        # The synonym list renames the second duplicate tool name, so the snapshot no
        # longer holds a duplicate.
        ("p18_duplicate_name", "synonym", "TD008"),
    }
)


def _load_mutations_module():
    spec = importlib.util.spec_from_file_location(
        "eval_mutations", Path(__file__).resolve().parent / "eval_mutations.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


em = _load_mutations_module()


def fired(snapshot_text: str) -> frozenset[str]:
    report = scan_tool_definitions(snapshot_text)
    return frozenset(f.rule_id for f in report.findings)


@dataclass
class PatternResult:
    pattern_id: str
    scope: str
    expected: frozenset[str]
    fired: frozenset[str]
    fetched: bool = True

    @property
    def counted(self) -> bool:
        return self.scope == "static" and self.fetched

    @property
    def missing(self) -> frozenset[str]:
        return self.expected - self.fired

    @property
    def extra(self) -> frozenset[str]:
        return self.fired - self.expected


@dataclass
class BenignResult:
    snapshots: Counter = field(default_factory=Counter)  # by origin: committed, local
    tools: int = 0
    unscannable: int = 0
    findings: Counter = field(default_factory=Counter)  # rule -> findings
    snapshots_hit: Counter = field(default_factory=Counter)  # rule -> snapshots


@dataclass(frozen=True)
class PositiveCounts:
    counted: int  # the denominator: static patterns from fetched sources
    any_expected: int  # at least one expected rule fired
    exact: int  # fired == expected
    with_extra: int  # at least one rule fired that was not expected
    outside: tuple[str, ...]  # pattern ids, scope outside
    unfetched: tuple[str, ...]  # pattern ids, scope static, source fetched: false


@dataclass
class MutationResult:
    # (rule, mutation) -> [detected, total], counted patterns only, artifacts left out
    rates: dict[tuple[str, str], list[int]] = field(default_factory=dict)
    # (pattern, mutation, rule) -> detected, for the MUTATION_ARTIFACTS cells
    artifacts: dict[tuple[str, str, str], bool] = field(default_factory=dict)
    counted_mutants: int = 0
    uncounted_mutants: int = 0  # mutants of patterns left out of the counts


@dataclass
class EvalReport:
    patterns: list[PatternResult]
    mutations: MutationResult
    mutants: int
    benign: BenignResult

    @property
    def positive_counts(self) -> PositiveCounts:
        return count_positives(self.patterns)


def evaluate_positives(manifest: Mapping[str, Any]) -> list[PatternResult]:
    sources = manifest["sources"]
    out = []
    for entry in manifest["patterns"]:
        text = em.fixture_path(entry["id"]).read_text(encoding="ascii")
        out.append(
            PatternResult(
                entry["id"],
                entry["scope"],
                frozenset(entry["expected"]),
                fired(text),
                sources[entry["source"]]["fetched"] is True,
            )
        )
    return out


def count_positives(patterns: Iterable[PatternResult]) -> PositiveCounts:
    patterns = list(patterns)
    counted = [p for p in patterns if p.counted]
    return PositiveCounts(
        counted=len(counted),
        any_expected=sum(1 for p in counted if p.expected & p.fired),
        exact=sum(1 for p in counted if p.expected == p.fired),
        with_extra=sum(1 for p in counted if p.extra),
        outside=tuple(p.pattern_id for p in patterns if p.scope != "static"),
        unfetched=tuple(
            p.pattern_id for p in patterns if p.scope == "static" and not p.fetched
        ),
    )


def evaluate_mutants(
    mutants: Iterable[Any],
    counted_ids: frozenset[str],
    artifacts: frozenset[tuple[str, str, str]] = MUTATION_ARTIFACTS,
) -> MutationResult:
    result = MutationResult()
    for m in mutants:
        if m.pattern_id not in counted_ids:
            result.uncounted_mutants += 1
            continue
        result.counted_mutants += 1
        got = fired(json.dumps(m.snapshot, ensure_ascii=True))
        for rule in m.expected:
            key = (m.pattern_id, m.mutation, rule)
            if key in artifacts:
                result.artifacts[key] = rule in got
                continue
            cell = result.rates.setdefault((rule, m.mutation), [0, 0])
            cell[1] += 1
            cell[0] += rule in got
    return result


def benign_files(committed_only: bool) -> list[tuple[str, Path]]:
    dirs = [("committed", COMMITTED_BENIGN)]
    if not committed_only:
        dirs.append(("local", LOCAL_BENIGN))
    return [
        (origin, p)
        for origin, d in dirs
        if d.is_dir()
        for p in sorted(d.glob("*.json"))
    ]


def evaluate_benign(files: Iterable[tuple[str, Path]]) -> BenignResult:
    result = BenignResult()
    for origin, path in files:
        result.snapshots[origin] += 1
        try:
            text = path.read_text(encoding="utf-8")
            report = scan_tool_definitions(text)
            result.tools += len(json.loads(text).get("tools", []))
        except (OSError, UnicodeDecodeError, ToolError, ValueError, AttributeError):
            result.unscannable += 1
            continue
        per_rule = Counter(f.rule_id for f in report.findings)
        result.findings.update(per_rule)
        result.snapshots_hit.update(per_rule.keys())
    return result


def build(committed_only: bool = False) -> EvalReport:
    manifest = em.load_manifest()
    mutants = em.generate(manifest)
    patterns = evaluate_positives(manifest)
    counted_ids = frozenset(p.pattern_id for p in patterns if p.counted)
    return EvalReport(
        patterns=patterns,
        mutations=evaluate_mutants(mutants, counted_ids),
        mutants=len(mutants),
        benign=evaluate_benign(benign_files(committed_only)),
    )


# --- formatting


def _ids(ids: Iterable[str]) -> str:
    return ",".join(sorted(ids)) or "-"


def _status(p: PatternResult) -> str:
    if p.scope != "static":
        return "outside"
    return "counted" if p.fetched else "unfetched"


def format_report(r: EvalReport) -> str:
    lines = ["== 1. Positives: expected vs fired"]
    head = f"{'pattern':40} {'status':10} {'expected':22} {'fired':22} {'missing':16} extra"
    lines.append(head)
    for p in r.patterns:
        lines.append(
            f"{p.pattern_id:40} {_status(p):10} {_ids(p.expected):22} "
            f"{_ids(p.fired):22} {_ids(p.missing):16} {_ids(p.extra)}"
        )
    c = r.positive_counts
    lines.append(f"counted: {c.counted} patterns (scope static, source fetched: true)")
    lines.append(f"  at least one expected rule fired: {c.any_expected}/{c.counted}")
    lines.append(f"  exact match (fired == expected): {c.exact}/{c.counted}")
    lines.append(f"  extra rules fired: {c.with_extra}/{c.counted}")
    lines.append(f"not counted, scope outside ({len(c.outside)}): {_ids(c.outside)}")
    lines.append(
        f"not counted, source fetched: false ({len(c.unfetched)}): {_ids(c.unfetched)}"
    )

    mr = r.mutations
    lines.append("")
    lines.append(
        f"== 2. Detection rate over mutations ({mr.counted_mutants} mutants of counted "
        f"patterns; {mr.uncounted_mutants} of {r.mutants} not counted)"
    )
    lines.append(f"{'rule':6} " + " ".join(f"{m[:12]:>12}" for m in em.MUTATIONS))
    for rule in RULE_IDS:
        cells = []
        for m in em.MUTATIONS:
            cell = mr.rates.get((rule, m))
            cells.append(f"{f'{cell[0]}/{cell[1]}' if cell else '-':>12}")
        lines.append(f"{rule:6} " + " ".join(cells))
    lines.append("columns: " + ", ".join(em.MUTATIONS))
    lines.append(f"mutation artifacts, not in the rates ({len(mr.artifacts)}):")
    for (pid, mutation, rule), hit in sorted(mr.artifacts.items()):
        lines.append(
            f"  {pid:40} {mutation:12} {rule:6} {'fired' if hit else 'not fired'}"
        )

    b = r.benign
    lines.append("")
    total = sum(b.snapshots.values())
    lines.append(
        f"== 3. Benign: {total} snapshots ({b.snapshots['committed']} committed, "
        f"{b.snapshots['local']} local), {b.tools} tools, {b.unscannable} unscannable"
    )
    lines.append(f"{'rule':6} {'findings':>9} {'snapshots':>10}")
    for rule in RULE_IDS:
        lines.append(f"{rule:6} {b.findings[rule]:>9} {b.snapshots_hit[rule]:>10}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--committed-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = build(committed_only=args.committed_only)
    except (OSError, ValueError, KeyError) as exc:
        print(f"cannot load the eval corpus: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(format_report(report), file=sys.stderr, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
