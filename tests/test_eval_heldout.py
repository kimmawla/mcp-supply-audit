"""scripts/eval_heldout.py runs, prints counts only, and writes benign findings to a TSV.

Checks that the script runs, never detection rates. The corpus used here is built in
tmp_path from the committed eval fixtures; nothing is added under tests/fixtures/.
"""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "tests/fixtures/eval"
HELDOUT = ROOT / "tests/fixtures/heldout"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


heldout = load_script("eval_heldout")

DUP_NAME = "zqvex_dup" + chr(0x200B)


def make_corpus(root: Path) -> None:
    manifest = yaml.safe_load((EVAL / "MANIFEST.yaml").read_text(encoding="ascii"))
    patterns = manifest["patterns"][:4]
    used = {p["source"] for p in patterns}
    (root / "positives").mkdir(parents=True)
    for p in patterns:
        shutil.copy(EVAL / "positives" / f"{p['id']}.json", root / "positives")
    sources = {k: v for k, v in manifest["sources"].items() if k in used}
    (root / "MANIFEST.yaml").write_text(
        yaml.safe_dump({"version": 1, "sources": sources, "patterns": patterns}),
        encoding="ascii",
    )
    benign = root / "benign"
    benign.mkdir()
    tool = {
        "name": DUP_NAME,
        "description": "Lists files.",
        "inputSchema": {"type": "object"},
    }
    (benign / "zqvex_dup.json").write_text(
        json.dumps({"tools": [tool, dict(tool)]}), encoding="ascii"
    )
    for path in sorted((EVAL / "benign").glob("*.json"))[:1]:
        shutil.copy(path, benign)


def test_script_runs_and_prints_counts_only(tmp_path, capsys):
    root = tmp_path / "heldout"
    make_corpus(root)
    tsv = tmp_path / "out/heldout-findings.tsv"
    assert heldout.main([], root=root, tsv=tsv) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err
    assert "at least one expected rule fired: " in err
    assert "exact match (fired == expected): " in err
    assert "extra rules fired: " in err
    assert "snapshots with any finding: " in err
    assert "zqvex_dup" not in err and ".json" not in err

    rows = tsv.read_text(encoding="ascii").splitlines()
    assert rows[0] == "file\trule\ttool"
    assert "zqvex_dup.json\tTD008\tzqvex_dup\\u200b" in rows[1:]
    assert f"{len(rows) - 1} rows" in err


def test_missing_corpus_exits_1(tmp_path, capsys):
    tsv = tmp_path / "heldout-findings.tsv"
    assert heldout.main([], root=tmp_path / "absent", tsv=tsv) == 1
    assert "held-out corpus not found" in capsys.readouterr().err
    assert not tsv.exists()


@pytest.mark.skipif(
    not (HELDOUT / "MANIFEST.yaml").is_file(),
    reason="held-out corpus not committed yet",
)
def test_script_runs_on_committed_heldout(tmp_path):
    assert heldout.main([], tsv=tmp_path / "heldout-findings.tsv") == 0
