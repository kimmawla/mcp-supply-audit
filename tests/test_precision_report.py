"""scripts/precision_report.py: namespace classes, TS006 tags, the seeded sample, and agreement
with check_typosquat on an invented reference list.

Every name here is invented (zqvex-*), never a publisher from the registry data. No network and
no generated reference file: the agreement test builds its own file in the compact format.
"""

import asyncio
import dataclasses
import importlib.util
import json
from collections import defaultdict
from pathlib import Path

import pytest

from mcp_supply_audit import typosquat_check as tc
from mcp_supply_audit.detectors import typosquat as ts

ROOT = Path(__file__).resolve().parents[1]

HOST = "io.github.zqvex-hosting"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "precision_report", ROOT / "scripts/precision_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr = load_script()


def name(raw: str) -> ts.Name:
    return ts.normalize(raw, "registry")


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("io.github.zqvex-lab/widget", "io.github.zqvex-lab/widgets", pr.SAME),
        ("io.github.zqvex-lab/widget", "io.github.ZQVEX-LAB/widget", pr.SAME),
        ("io.github.zqvex-lab/widget", "net.zqvex-tools/widget", pr.DIFFERENT),
        (f"{HOST}/alice-widget", f"{HOST}/alice-widgets", pr.PLATFORM),
        (f"{HOST}/widget", "net.zqvex-tools/widget", pr.PLATFORM),
        ("net.zqvex-tools/widget", f"{HOST.upper()}/widget", pr.PLATFORM),
    ],
)
def test_classify(a, b, expected):
    assert pr.classify(name(a), name(b), frozenset({HOST})) == expected


@pytest.mark.parametrize(
    "a,b,tag",
    [
        ("com.zqvexa/widget", "io.zqvexa/widget", "tld-variant"),
        ("io.zqvexa/widget", "io.zqvexb/widget", "distance-1"),
        ("io.zqvexa/widget", "io.zqvexbb/widget", "distance-2"),
        ("zqvex.rnrnrn/widget", "zqvex.mmm/widget", "lookalike"),
    ],
)
def test_ts006_tag(a, b, tag):
    assert pr.ts006_tag(name(a), name(b)) == tag
    assert pr.ts006_tag(name(b), name(a)) == tag


def test_tld_variant_needs_the_rest_of_the_namespace_equal():
    assert pr.ts006_tag(name("com.zqvexa/w"), name("io.zqvexb/w")) != "tld-variant"


def test_top_namespaces_counts_a_pair_once_per_namespace():
    pairs = [
        (name("io.zqvexa/one"), name("io.zqvexa/ones")),
        (name("io.zqvexa/two"), name("com.zqvexa/two")),
    ]
    assert pr.top_namespaces(pairs) == {"io.zqvexa": 2, "com.zqvexa": 1}


POOL = [(f"io.zqvexa/w{i}", f"io.zqvexb/w{i}") for i in range(100)]


def test_sample_is_seeded_and_sized():
    first = pr.sample_pairs(POOL, 40, 7, "TS003")
    assert len(first) == 40
    assert set(first) <= set(POOL)
    assert first == pr.sample_pairs(list(reversed(POOL)), 40, 7, "TS003")
    assert first != pr.sample_pairs(POOL, 40, 8, "TS003")
    assert first != pr.sample_pairs(POOL, 40, 7, "TS006")


def test_sample_larger_than_pool_returns_the_pool():
    assert pr.sample_pairs(POOL[:3], 40, 0, "TS003") == sorted(POOL[:3])
    assert pr.sample_pairs(POOL, 0, 0, "TS003") == []


def test_sample_must_not_be_negative():
    with pytest.raises(SystemExit):
        pr.main(["--sample", "-1"])


# --- the report and check_typosquat agree (same rule functions, same counts)

# One or more pairs for every tuning: A (same namespace, platform), B (TS005), C (case-only
# namespace), D (distance 1; distance 2 inside and outside io.github.; tld-variant at distance
# 2 and 3, a series; lookalike; hyphen), E (equal and different owner tokens).
AGREEMENT_NAMES = [
    f"{HOST}/zqa-widget",
    f"{HOST}/zqb-widget",
    f"{HOST}/mcp-widget-tools",
    f"{HOST}/widget-tools",
    "com.zqvexlabxy/gadget-hub",
    "com.zqvexlab/gadget-hub",
    f"{HOST}/alice-widget",
    f"{HOST}/alice-widgets",
    f"{HOST}/Alice-Widget",
    f"{HOST}/alice-widget-mcp",
    f"{HOST.upper()}/alice-widget",
    "io.github.zqvex-lab/gadget-hub",
    "io.github.zqvex-lab/gadget-hubs",
    "io.github.zqvex-lab/gadget-hub-mcp",
    "io.github.zqvex-lab/data-sync",
    "io.github.zqvex-lab/sync-data",
    "io.github.ZQVEX-LAB/gadget-hub",
    "io.github.zqvex-labs/gadget-hub",
    "io.github.zqvex-labxy/gadget-hub",
    "io.github.zqvexlab/gadget-hub",
    "com.zqvexnet/relay-hub",
    "io.zqvexnet/relay-hub",
    "dev.zqvexnet/relay-hub",
    "io.zqvexm/relay-node",
    "io.zqvexrn/relay-node",
]


def reference_file(names: list[str]) -> bytes:
    doc = {
        "curated": [],
        "generated_at": "2026-11-03",
        "listed": {
            "registry": {
                "names": sorted(names),
                "page_cap": 1,
                "page_size": 100,
                "pages_fetched": 1,
                "partial": False,
                "source": "mcp-registry-crawl",
            }
        },
        "sources": [
            {
                "id": "mcp-registry-crawl",
                "name": "MCP Registry server list",
                "type": "listed-not-curated",
                "url": "https://registry.modelcontextprotocol.io/v0/servers",
            }
        ],
    }
    return json.dumps(doc, sort_keys=True, indent=2).encode("ascii")


def pairs_from_check_typosquat(monkeypatch, names):
    """Unordered pairs per rule from check_typosquat, each name against a file of the rest."""
    pairs = defaultdict(set)
    for raw in names:
        rest = reference_file([n for n in names if n != raw])
        monkeypatch.setattr(tc, "read_reference_bytes", lambda rest=rest: rest)
        report = asyncio.run(tc.check_typosquat(raw, "registry"))
        assert not any("further match" in n for n in report.notes)
        for f in report.findings:
            other = f.evidence.rsplit("similar to ", 1)[1]
            pairs[f.rule_id].add(frozenset((raw, other)))
    return pairs


def pairs_from_report(names, tuning):
    refs = tc.parse_reference_names(reference_file(names)).by_ecosystem["registry"]
    run = pr.collect_pairs(refs, pr.CandidateIndex(refs), tuning)
    pairs = defaultdict(set)
    for rule_id, _, pair in run.pairs:
        pairs[rule_id].add(pair)
    return pairs


def agreement_refs():
    return tc.parse_reference_names(reference_file(AGREEMENT_NAMES)).by_ecosystem[
        "registry"
    ]


def test_series_tags_a_name_part_shared_by_three_near_namespaces(monkeypatch):
    monkeypatch.setattr(ts, "load_platform_namespaces", lambda: frozenset({HOST}))
    refs = agreement_refs()
    index = pr.CandidateIndex(refs)
    run = pr.collect_pairs(refs, index, ts.REGISTRY_TUNING)
    series = pr.series_pairs(run.pairs, index, ts.REGISTRY_TUNING)
    parts = {next(iter(pair)).split("/", 1)[1] for _, _, pair in series}
    # relay-hub: com, io and dev .zqvexnet (tld-variants); gadget-hub: the zqvex-lab family of
    # near namespaces. relay-node has only two namespaces, so it is not a series.
    assert parts == {"relay-hub", "gadget-hub"}
    assert series <= set(run.pairs)  # tagged, never removed


def test_owner_token_exemptions_are_counted(monkeypatch):
    monkeypatch.setattr(ts, "load_platform_namespaces", lambda: frozenset({HOST}))
    refs = agreement_refs()
    without_e = pr.collect_pairs(
        refs,
        pr.CandidateIndex(refs),
        dataclasses.replace(ts.REGISTRY_TUNING, platform_owner_token=False),
    )
    counts = pr.owner_token_exempted(without_e.pairs, frozenset({HOST}))
    assert counts["TS003"] >= 1 and counts["TS004"] >= 1
    assert set(counts) <= {"TS003", "TS004"}


def test_report_and_check_typosquat_give_identical_counts(monkeypatch):
    monkeypatch.setattr(ts, "load_platform_namespaces", lambda: frozenset({HOST}))
    from_tool = pairs_from_check_typosquat(monkeypatch, AGREEMENT_NAMES)
    from_report = pairs_from_report(AGREEMENT_NAMES, ts.REGISTRY_TUNING)
    assert from_report == from_tool
    counts = {r: len(from_report[r]) for r in ts.RULE_IDS}
    assert counts == {r: len(from_tool[r]) for r in ts.RULE_IDS}
    assert counts["TS003"] and counts["TS006"]


def test_untuned_run_differs_by_the_tuning(monkeypatch):
    monkeypatch.setattr(ts, "load_platform_namespaces", lambda: frozenset({HOST}))
    before = pairs_from_report(AGREEMENT_NAMES, ts.UNTUNED)
    after = pairs_from_report(AGREEMENT_NAMES, ts.REGISTRY_TUNING)
    lab, case_lab = "io.github.zqvex-lab/gadget-hub", "io.github.ZQVEX-LAB/gadget-hub"
    # A: same-namespace pairs go, platform pairs with different owner tokens stay.
    assert frozenset((lab, f"{lab}s")) in before["TS003"] - after["TS003"]
    assert frozenset((f"{HOST}/zqa-widget", f"{HOST}/zqb-widget")) in after["TS003"]
    tools = frozenset((f"{HOST}/mcp-widget-tools", f"{HOST}/widget-tools"))
    assert tools in after["TS004"]
    # E: equal owner tokens on a platform namespace go.
    alice = frozenset((f"{HOST}/alice-widget", f"{HOST}/alice-widgets"))
    assert alice in before["TS003"] and alice not in after["TS003"]
    # B: TS005 is gone from the registry tier.
    assert before["TS005"] and not after["TS005"]
    # C: case-only namespace pairs go, even on a platform namespace.
    assert frozenset((lab, case_lab)) in before["TS001"]
    assert all(
        name(a).raw_part != name(b).raw_part for a, b in map(tuple, after["TS001"])
    )
    # D: distance 2 goes outside io.github. and stays inside it; tld-variant at distance 3
    # is new.
    outside = frozenset(("com.zqvexlabxy/gadget-hub", "com.zqvexlab/gadget-hub"))
    assert outside in before["TS006"] and outside not in after["TS006"]
    inside = "io.github.zqvex-labxy/gadget-hub"  # 2 edits from every other namespace
    assert any(inside in pair for pair in after["TS006"])
    tld3 = "dev.zqvexnet/relay-hub"  # first label 3 edits from com and io
    assert not any(tld3 in pair for pair in before["TS006"])
    assert any(tld3 in pair for pair in after["TS006"])


# --- review sheet and tally (invented names; LOCAL_DIR is a tmp folder)


@pytest.fixture
def local(tmp_path, monkeypatch):
    folder = tmp_path / "local_fixtures"
    folder.mkdir()
    monkeypatch.setattr(pr, "LOCAL_DIR", folder)
    return folder


def fake_pairs(n: int, rule_id: str = "TS003") -> pr.Pairs:
    out = {}
    for i in range(n):
        a, b = name(f"io.zqvexa/w{i:03}"), name(f"io.zqvexb/w{i:03}")
        out[(rule_id, "name.namespace", frozenset((a.raw, b.raw)))] = (a, b)
    return out


def test_review_rows_take_every_pair_up_to_the_limit():
    pairs = fake_pairs(3)
    # The same rule and pair at a second location is one row.
    a, b = next(iter(pairs.values()))
    pairs[("TS003", "name", frozenset((a.raw, b.raw)))] = (a, b)
    pairs.update(fake_pairs(2, "TS006"))
    rows = pr.review_rows(pairs, seed=0)
    assert [r[0] for r in rows] == [1, 2, 3, 4, 5]
    assert [r[1] for r in rows] == ["TS003"] * 3 + ["TS006"] * 2
    assert all(r[2] < r[3] for r in rows)
    assert len(pr.review_rows(fake_pairs(pr.REVIEW_SHEET_SIZE), 0)) == 100


def test_review_rows_sample_is_seeded_above_the_limit():
    pairs = fake_pairs(250)
    first = pr.review_rows(pairs, seed=3)
    assert len(first) == pr.REVIEW_SHEET_SIZE == 100
    assert first == pr.review_rows(dict(reversed(list(pairs.items()))), seed=3)
    assert first != pr.review_rows(pairs, seed=4)
    everything = {r[1:] for r in pr.review_rows(fake_pairs(250), seed=3)}
    assert {(f"io.zqvexa/w{i:03}", f"io.zqvexb/w{i:03}") for i in range(250)} >= {
        r[2:] for r in first
    }
    assert len(everything) == 100


def read_rows(path):
    return [line.split("\t") for line in path.read_text(encoding="ascii").splitlines()]


def test_write_review_sheet_has_header_and_empty_labels(local):
    target = local / "sheets" / "review.tsv"
    pr.write_review_sheet(target, pr.review_rows(fake_pairs(2), 0))
    rows = read_rows(target)
    assert rows[0] == list(pr.SHEET_HEADER)
    assert rows[1] == ["1", "TS003", "io.zqvexa/w000", "io.zqvexb/w000", ""]
    assert len(rows) == 3


def test_review_sheet_cells_escape_what_could_break_a_row(local):
    tab, zwsp = chr(9), chr(0x200B)
    rows = [(1, "TS003", f"io.zqvexa/w{tab}x", f"io.zqvexb/w{zwsp}x")]
    target = local / "review.tsv"
    pr.write_review_sheet(target, rows)
    bs = chr(92)
    assert read_rows(target)[1] == [
        "1",
        "TS003",
        f"io.zqvexa/w{bs}u0009x",
        f"io.zqvexb/w{bs}u200bx",
        "",
    ]


@pytest.mark.parametrize(
    "where",
    [
        lambda local, tmp: tmp / "outside.tsv",
        lambda local, tmp: local / ".." / "escaped.tsv",
        lambda local, tmp: tmp / "elsewhere" / "local_fixtures" / "x.tsv",
    ],
)
def test_review_sheet_refuses_paths_outside_local_fixtures(local, tmp_path, where):
    target = where(local, tmp_path)
    with pytest.raises(pr.SheetError):
        pr.write_review_sheet(target, pr.review_rows(fake_pairs(1), 0))
    assert not target.exists()


def test_review_sheet_refuses_a_symlink_out_of_local_fixtures(local, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (local / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(pr.SheetError):
        pr.write_review_sheet(
            local / "link" / "x.tsv", pr.review_rows(fake_pairs(1), 0)
        )
    assert not (outside / "x.tsv").exists()


def test_review_sheet_never_overwrites(local):
    target = local / "review.tsv"
    target.write_text("labelled work\n", encoding="ascii")
    with pytest.raises(pr.SheetError):
        pr.write_review_sheet(target, pr.review_rows(fake_pairs(1), 0))
    assert target.read_text(encoding="ascii") == "labelled work\n"


def run_main(monkeypatch, argv):
    monkeypatch.setattr(ts, "load_platform_namespaces", lambda: frozenset({HOST}))
    data = reference_file(AGREEMENT_NAMES)
    monkeypatch.setattr(tc, "read_reference_bytes", lambda: data)
    return pr.main(argv)


def test_main_writes_every_registry_tier_pair(monkeypatch, local, capsys):
    target = local / "review.tsv"
    assert run_main(monkeypatch, ["--review-sheet", str(target)]) == 0
    rows = read_rows(target)[1:]
    expected = pairs_from_report(AGREEMENT_NAMES, ts.REGISTRY_TUNING)
    assert len(rows) == sum(len(v) for v in expected.values()) <= 100
    for _, rule_id, a, b, label in rows:
        assert frozenset((a, b)) in expected[rule_id]
        assert label == ""
    assert "review sheet: " in capsys.readouterr().err


def test_main_refuses_an_outside_path_before_running(monkeypatch, local, tmp_path):
    target = tmp_path / "outside.tsv"
    assert run_main(monkeypatch, ["--review-sheet", str(target)]) == 1
    assert not target.exists()


def test_review_sheet_and_tally_are_exclusive(local):
    with pytest.raises(SystemExit):
        pr.main(["--review-sheet", str(local / "a"), "--tally", str(local / "b")])


def labelled(local, labels, rules=None):
    path = local / "labelled.tsv"
    lines = ["\t".join(pr.SHEET_HEADER)]
    for i, label in enumerate(labels, 1):
        rule_id = rules[i - 1] if rules else "TS003"
        lines.append(f"{i}\t{rule_id}\tio.zqvexa/w{i}\tio.zqvexb/w{i}\t{label}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def test_tally_counts_per_label_and_rule(local, capsys):
    path = labelled(
        local,
        ["plausible", "legitimate", "legitimate", "unclear", " plausible "],
        ["TS003", "TS003", "TS006", "TS006", "TS001"],
    )
    tally = pr.read_tally(path)
    assert tally.reviewed == 5
    assert tally.by_label == {"plausible": 2, "legitimate": 2, "unclear": 1}
    assert tally.by_rule["TS003"] == {"plausible": 1, "legitimate": 1}
    assert tally.by_rule["TS006"] == {"legitimate": 1, "unclear": 1}
    assert pr.main(["--tally", str(path)]) == 0
    err = capsys.readouterr().err
    assert "pairs reviewed: 5" in err
    assert "zqvex" not in err  # counts only, never names


@pytest.mark.parametrize(
    "labels",
    [
        ["plausible", ""],
        ["plausible", "   "],
        ["Plausible"],
        ["safe"],
        ["malicious", "plausible"],
        ["plausible", "legitimate?"],
    ],
)
def test_tally_rejects_blank_or_unknown_labels(local, capsys, labels):
    path = labelled(local, labels)
    with pytest.raises(pr.SheetError):
        pr.read_tally(path)
    assert pr.main(["--tally", str(path)]) == 1
    err = capsys.readouterr().err
    assert "tally rejected" in err and "pairs reviewed" not in err
    assert "zqvex" not in err


@pytest.mark.parametrize(
    "body",
    [
        "",
        "id\trule\tname_a\tname_b\n1\tTS003\ta\tb\tplausible\n",
        "\t".join(pr.SHEET_HEADER) + "\n",
        "\t".join(pr.SHEET_HEADER) + "\n1\tTS003\tio.zqvexa/w\tplausible\n",
        "\t".join(pr.SHEET_HEADER)
        + "\n1\tTS099\tio.zqvexa/w\tio.zqvexb/w\tplausible\n",
        "\t".join(pr.SHEET_HEADER)
        + "\n1\tTS003\tio.zqvexa/w\tio.zqvexb/w\tplausible"
        + "\n1\tTS003\tio.zqvexa/x\tio.zqvexb/x\tunclear\n",
    ],
)
def test_tally_rejects_malformed_sheets(local, body):
    path = local / "bad.tsv"
    path.write_text(body, encoding="ascii")
    with pytest.raises(pr.SheetError):
        pr.read_tally(path)


def test_tally_error_names_lines_not_values(local):
    path = labelled(local, ["plausible", "zqvex-not-a-label", ""])
    with pytest.raises(pr.SheetError) as info:
        pr.read_tally(path)
    message = str(info.value)
    assert "line 3" in message and "line 4" in message
    assert "zqvex" not in message


def test_tally_refuses_paths_outside_local_fixtures(local, tmp_path):
    outside = tmp_path / "labelled.tsv"
    outside.write_text("\t".join(pr.SHEET_HEADER) + "\n", encoding="ascii")
    with pytest.raises(pr.SheetError):
        pr.read_tally(outside)
    assert pr.main(["--tally", str(outside)]) == 1
