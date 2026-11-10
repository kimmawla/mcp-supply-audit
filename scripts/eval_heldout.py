"""Held-out evaluation for TD001-TD008: counts only, over tests/fixtures/heldout/.

Dev-only: run by hand. Never imported by src/. Offline and deterministic: reads committed
fixtures only, sends no requests, uses no randomness. Prints counts to stderr. The numbers
are for local review (CLAUDE.md: benchmark output stays local).

Inputs (same layout and manifest schema as tests/fixtures/eval/)
  tests/fixtures/heldout/MANIFEST.yaml      version: 1, sources (with fetched), patterns
                                            (id, source, scope, expected)
  tests/fixtures/heldout/positives/*.json   one snapshot per pattern id
  tests/fixtures/heldout/benign/*.json      benign snapshots

Output
  Positives, over the counted patterns (scope static, source fetched: true): at least one
  expected rule fired, exact match, extra rules fired. No OUT_OF_SCOPE or artifact cells:
  the held-out set is scored as it stands.
  Benign: snapshots, snapshots with any finding, findings per rule.
  For each benign finding, one row (file, rule, tool) goes to
  local_fixtures/heldout-findings.tsv, overwritten each run; only the row count is printed.
  Tool names are target text: written with every character outside printable ASCII (and
  space) as a visible escape, so a name cannot break a row.

Every snapshot goes through scan_tool_definitions, the same entry point the tool uses.

Usage: uv run scripts/eval_heldout.py
Exit status: 0 printed, 1 corpus missing or unreadable.
"""

import argparse
import csv
import importlib.util
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit.detectors.tool_defs import RULES, scan_tool_definitions

ROOT = Path(__file__).resolve().parents[1]
HELDOUT = ROOT / "tests/fixtures/heldout"
FINDINGS_TSV = ROOT / "local_fixtures/heldout-findings.tsv"
TSV_HEADER = ("file", "rule", "tool")
RULE_IDS = tuple(rule_id for rule_id, _ in RULES)
_TOOL_INDEX = re.compile(r"tools\[(\d+)\]")


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


etd = _load_script("eval_tool_defs")
_cell = _load_script("precision_report")._cell


class CorpusMissing(ValueError):
    """The held-out corpus is absent. The message names no file content."""


@dataclass
class BenignResult:
    snapshots: int = 0
    unscannable: int = 0
    hit: int = 0  # snapshots with at least one finding
    findings: Counter = field(default_factory=Counter)  # rule -> findings
    rows: list[tuple[str, str, str]] = field(default_factory=list)  # file, rule, tool


@dataclass
class HeldoutReport:
    positives: Any  # eval_tool_defs.PositiveCounts
    benign: BenignResult


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "MANIFEST.yaml"
    if not path.is_file():
        raise CorpusMissing("held-out MANIFEST.yaml not found")
    data = yaml.safe_load(path.read_text(encoding="ascii"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("held-out MANIFEST.yaml: expected a mapping with version: 1")
    return data


def evaluate_positives(manifest: dict[str, Any], root: Path) -> list:
    sources = manifest["sources"]
    out = []
    for entry in manifest["patterns"]:
        text = (root / "positives" / f"{entry['id']}.json").read_text(encoding="utf-8")
        out.append(
            etd.PatternResult(
                entry["id"],
                entry["scope"],
                frozenset(entry["expected"]),
                etd.fired(text),
                sources[entry["source"]]["fetched"] is True,
            )
        )
    return out


def _tool_name(tools: Any, location: str) -> str:
    m = _TOOL_INDEX.match(location)
    if not m or not isinstance(tools, list) or int(m.group(1)) >= len(tools):
        return "-"
    tool = tools[int(m.group(1))]
    name = tool.get("name") if isinstance(tool, dict) else None
    return _cell(name) if isinstance(name, str) and name else "-"


def evaluate_benign(files: Iterable[Path]) -> BenignResult:
    result = BenignResult()
    for path in files:
        result.snapshots += 1
        try:
            text = path.read_text(encoding="utf-8")
            report = scan_tool_definitions(text)
            tools = json.loads(text).get("tools")
        except (OSError, UnicodeDecodeError, ToolError, ValueError, AttributeError):
            result.unscannable += 1
            continue
        if report.findings:
            result.hit += 1
        for f in report.findings:
            result.findings[f.rule_id] += 1
            result.rows.append(
                (_cell(path.name), f.rule_id, _tool_name(tools, f.location))
            )
    return result


def build(root: Path = HELDOUT) -> HeldoutReport:
    manifest = load_manifest(root)
    patterns = evaluate_positives(manifest, root)
    benign_dir = root / "benign"
    files = sorted(benign_dir.glob("*.json")) if benign_dir.is_dir() else []
    return HeldoutReport(
        positives=etd.count_positives(patterns, out_of_scope={}),
        benign=evaluate_benign(files),
    )


def write_findings(path: Path, rows: list[tuple[str, str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(TSV_HEADER)
        writer.writerows(rows)


def format_report(r: HeldoutReport) -> str:
    c = r.positives
    b = r.benign
    lines = [
        (
            f"== Held-out positives: {c.counted} counted (scope static, source fetched: "
            f"true); {len(c.outside)} scope outside, {len(c.unfetched)} unfetched, "
            "not counted"
        ),
        f"  at least one expected rule fired: {c.any_expected}/{c.counted}",
        f"  exact match (fired == expected): {c.exact}/{c.exact_counted}",
        f"  extra rules fired: {c.with_extra}/{c.counted}",
        "",
        f"== Held-out benign: {b.snapshots} snapshots, {b.unscannable} unscannable",
        f"  snapshots with any finding: {b.hit}/{b.snapshots}",
        f"{'rule':6} {'findings':>9}",
    ]
    lines += [f"{rule:6} {b.findings[rule]:>9}" for rule in RULE_IDS]
    return "\n".join(lines) + "\n"


def main(
    argv: list[str] | None = None, root: Path = HELDOUT, tsv: Path = FINDINGS_TSV
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)
    try:
        report = build(root)
    except CorpusMissing:
        print(
            "held-out corpus not found: tests/fixtures/heldout/MANIFEST.yaml",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"cannot load the held-out corpus: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(format_report(report), file=sys.stderr, end="")
    write_findings(tsv, report.benign.rows)
    print(
        f"benign findings written to local_fixtures/heldout-findings.tsv: "
        f"{len(report.benign.rows)} rows",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
