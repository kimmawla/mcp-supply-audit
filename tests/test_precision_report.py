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
