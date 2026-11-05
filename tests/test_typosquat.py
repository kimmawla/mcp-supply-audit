"""check_typosquat: TS001-TS006, the reference file loader, coverage, notes, and the build script.

Every test reads tests/fixtures/typosquat/reference_names.json (15 names in the compact format),
never the generated file; one test checks the packaged file's shape when it exists. Positives
are built by mutating a fixture reference name in test code. No network: the build script's
crawl is driven with fake pages or respx.
"""

import ast
import asyncio
import importlib.util
import json
import re
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
import respx
import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit import typosquat_check as tc
from mcp_supply_audit.detectors import typosquat as ts
from mcp_supply_audit.findings import Assessment, SkipDetail, SkipReason
from mcp_supply_audit.owasp import OWASP_MCP_TOP_10

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src/mcp_supply_audit/data"
SPEC = ROOT / "docs/rules-typosquat.md"
FIXTURE = ROOT / "tests/fixtures/typosquat/reference_names.json"

ZWSP = chr(0x200B)
RLO = chr(0x202E)
CYRILLIC_A = chr(0x0430)


@pytest.fixture(autouse=True)
def fixture_reference_file(monkeypatch):
    monkeypatch.setattr(tc, "read_reference_bytes", FIXTURE.read_bytes)


def loaded() -> tc.ReferenceNames:
    return tc.parse_reference_names(FIXTURE.read_bytes())


def reference_names(ecosystem: str) -> list[str]:
    return [r.name.raw for r in loaded().by_ecosystem[ecosystem]]


def check(name, ecosystem, **kw):
    return asyncio.run(tc.check_typosquat(name, ecosystem, **kw))


def rule_ids(report) -> set[str]:
    return {f.rule_id for f in report.findings}


def skipped(report) -> dict[str, tuple[SkipReason, SkipDetail | None]]:
    return {s.check: (s.reason, s.detail) for s in report.coverage.skipped}


def fresh() -> date:
    return loaded().generated_at


# --- one positive per rule, built by mutating a reference name


def pypi_ref(name: str) -> str:
    assert name in reference_names("pypi"), name
    return name


def npm_ref(name: str) -> str:
    assert name in reference_names("npm"), name
    return name


def test_ts001_separator_variant():
    ref = pypi_ref("mcp-server-fetch")
    report = check(ref.replace("-", "_"), "pypi", today=fresh())
    assert "TS001" in rule_ids(report)
    assert report.assessment is Assessment.FINDINGS_PRESENT


def test_ts002_confusable_pair():
    ref = pypi_ref("mcp-server-time")
    report = check(ref.replace("m", "rn").replace("rncp", "mcp"), "pypi", today=fresh())
    assert "TS002" in rule_ids(report)


def test_ts003_one_deletion():
    ref = pypi_ref("mcp-server-fetch")
    report = check(ref[:-1], "pypi", today=fresh())
    assert "TS003" in rule_ids(report)


def test_ts003_transposition_counts_as_one():
    ref = pypi_ref("fastmcp")
    swapped = ref[:1] + ref[2] + ref[1] + ref[3:]
    report = check(swapped, "pypi", today=fresh())
    assert "TS003" in rule_ids(report)


def test_ts004_suffix_added():
    ref = pypi_ref("httpx")
    report = check(f"{ref}-mcp", "pypi", today=fresh())
    assert "TS004" in rule_ids(report)


def test_ts005_tokens_reordered():
    ref = pypi_ref("mcp-server-fetch")
    report = check("-".join(reversed(ref.split("-"))), "pypi", today=fresh())
    assert "TS005" in rule_ids(report)


def test_ts006_scope_one_edit_away():
    ref = npm_ref("@modelcontextprotocol/server-memory")
    scope, package = ref[1:].split("/")
    report = check(f"@{scope[:-1]}/{package}", "npm", today=fresh())
    assert "TS006" in rule_ids(report)
    (finding,) = [f for f in report.findings if f.rule_id == "TS006"]
    assert finding.location == "name.scope"


def test_findings_say_similar_never_a_verdict():
    report = check("mcp-server-fetc", "pypi", today=fresh())
    for f in report.findings:
        text = json.dumps(f.to_dict()).lower()
        assert "similar to" in text
        for word in ("typosquat", "malicious", "impersonat"):
            assert word not in text


# --- exact reference names, short names, hostile names


@pytest.mark.parametrize("ecosystem", ["pypi", "npm"])
def test_exact_reference_name_gives_no_finding_and_a_note(ecosystem):
    for ref in reference_names(ecosystem):
        report = check(ref, ecosystem, today=fresh())
        assert report.findings == ()
        assert report.assessment is Assessment.NO_FINDINGS_DETECTED
        assert tc.REFERENCE_ENTRY_NOTE in report.notes
        assert set(skipped(report)) == set(ts.RULE_IDS)
        assert all(
            v == (SkipReason.NOT_APPLICABLE, SkipDetail.REFERENCE_ENTRY)
            for v in skipped(report).values()
        )


def test_short_name_skips_distance_rules_but_ts001_runs():
    report = check("htpx", "pypi", today=fresh())
    assert report.coverage.ran == ("TS001",)
    for rule_id in ("TS002", "TS003", "TS004", "TS005", "TS006"):
        assert skipped(report)[rule_id] == (
            SkipReason.NOT_APPLICABLE,
            SkipDetail.NAME_TOO_SHORT,
        )
    assert report.coverage.to_dict()["skipped"][0]["detail"] == "name too short"


def test_short_name_still_gets_ts001():
    # 4 characters, equal to nothing in the list; a case variant of a short reference
    # would fire. Built from a synthetic reference set so the list need not hold one.
    refs = [ts.Reference(ts.normalize("abcd", "pypi"), "s", ts.DEPENDENCY)]
    matches, coverage = tc.run_rules(ts.normalize("ABCD", "pypi"), refs)
    assert [m.finding.rule_id for m in matches] == ["TS001"]
    assert coverage.ran == ("TS001",)


def test_scoped_npm_length_is_measured_on_the_package_part():
    report = check("@modelcontextprotocol/abc", "npm", today=fresh())
    assert skipped(report)["TS003"] == (
        SkipReason.NOT_APPLICABLE,
        SkipDetail.NAME_TOO_SHORT,
    )


def test_unscoped_name_skips_ts006():
    report = check("mcp-server-fetc", "pypi", today=fresh())
    assert skipped(report)["TS006"] == (SkipReason.NOT_APPLICABLE, SkipDetail.NO_SCOPE)


@pytest.mark.parametrize(
    "name",
    [
        f"mcp-server{ZWSP}-fetch",
        f"mcp-server-fetch{RLO}",
        f"mcp-server-fet{CYRILLIC_A}h",
        "../mcp-server-fetch",
        "mcp server fetch",
        "a" * 5000,
        "",
        None,
        123,
        ["mcp-server-fetch"],
    ],
)
@pytest.mark.parametrize("ecosystem", ["pypi", "npm", "registry"])
def test_hostile_names_are_rejected_by_validation(name, ecosystem):
    with pytest.raises(ToolError) as info:
        check(name, ecosystem)
    if isinstance(name, str) and name:
        assert name not in str(info.value)


@pytest.mark.parametrize("ecosystem", ["cargo", "", None, "PYPI ", 1])
def test_unknown_ecosystem_is_rejected(ecosystem):
    with pytest.raises(ToolError):
        check("mcp-server-fetch", ecosystem)


def test_registry_without_reference_names_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(
        tc, "read_reference_bytes", lambda: mutated(lambda d: d.update(listed={}))
    )
    report = check("io.github.example/weather", "registry", today=fresh())
    assert report.coverage.ran == ()
    assert all(
        v == (SkipReason.NOT_DETERMINABLE, SkipDetail.NO_REFERENCE_NAMES)
        for v in skipped(report).values()
    )


# --- data sources and the stale note


def test_report_records_reference_date_and_count():
    report = check("mcp-server-fetc", "pypi", today=fresh())
    (source,) = report.data_sources
    assert source.name == "data/reference_names.json"
    assert source.as_of == loaded().generated_at.isoformat()
    assert source.entry_count == loaded().entry_count
    assert report.to_dict()["data_sources"][0]["entry_count"] == source.entry_count


def test_stale_file_adds_note_without_changing_assessment():
    as_of = loaded().generated_at
    fresh_report = check("zzzzz-unrelated", "pypi", today=as_of + timedelta(days=120))
    stale_report = check("zzzzz-unrelated", "pypi", today=as_of + timedelta(days=121))
    assert fresh_report.notes == ()
    assert stale_report.notes == (tc.stale_note(as_of),)
    assert as_of.isoformat() in stale_report.notes[0]
    assert stale_report.assessment is Assessment.NO_FINDINGS_DETECTED


# --- malformed, unreadable, or crashing


def valid_document() -> dict:
    return json.loads(FIXTURE.read_bytes())


def mutated(change) -> bytes:
    doc = valid_document()
    change(doc)
    return json.dumps(doc, sort_keys=True).encode()


MALFORMED = {
    "not json": b"{not json",
    "non-ascii": json.dumps(valid_document(), ensure_ascii=False)
    .replace("fastmcp", f"f{CYRILLIC_A}stmcp")
    .encode(),
    "too deep": b"[" * 100 + b"]" * 100,
    "top-level list": b"[]",
    "missing curated": mutated(lambda d: d.pop("curated")),
    "old entries key": mutated(lambda d: d.update(entries=d.pop("curated"))),
    "extra key": mutated(lambda d: d.update(extra=1)),
    "bad date": mutated(lambda d: d.update(generated_at="yesterday")),
    "empty sources": mutated(lambda d: d.update(sources=[])),
    "unknown source": mutated(lambda d: d["curated"][0].update(source="nowhere")),
    "unknown source type": mutated(lambda d: d["sources"][0].update(type="x")),
    "source without id": mutated(lambda d: d["sources"][0].pop("id")),
    "duplicate source id": mutated(lambda d: d["sources"].append(d["sources"][0])),
    "invalid name": mutated(lambda d: d["curated"][0].update(name="../x")),
    "curated entry with listed source": mutated(
        lambda d: d["curated"][0].update(source="mcp-registry-crawl")
    ),
    "curated entry with source_type": mutated(
        lambda d: d["curated"][0].update(source_type="dependency")
    ),
    "duplicate entry": mutated(lambda d: d["curated"].append(dict(d["curated"][0]))),
    "http source": mutated(lambda d: d["sources"][0].update(url="http://x.example")),
    "listed not a mapping": mutated(lambda d: d.update(listed=[])),
    "listed pypi names": mutated(
        lambda d: d["listed"].update(pypi=d["listed"]["registry"])
    ),
    "listed names unsorted": mutated(
        lambda d: d["listed"]["registry"]["names"].reverse()
    ),
    "listed name repeated": mutated(
        lambda d: d["listed"]["registry"]["names"].insert(
            0, "com.example/calendar-sync"
        )
    ),
    "listed name not a string": mutated(
        lambda d: d["listed"]["registry"]["names"].insert(0, 1)
    ),
    "listed invalid name": mutated(
        lambda d: d["listed"]["registry"]["names"].insert(0, "../x")
    ),
    "listed with curated source": mutated(
        lambda d: d["listed"]["registry"].update(source="dependency/httpx")
    ),
    "listed without partial": mutated(lambda d: d["listed"]["registry"].pop("partial")),
    "partial not a bool": mutated(lambda d: d["listed"]["registry"].update(partial=1)),
    "pages over cap": mutated(
        lambda d: d["listed"]["registry"].update(pages_fetched=101)
    ),
    "partial below cap": mutated(
        lambda d: d["listed"]["registry"].update(partial=True)
    ),
    "page size zero": mutated(lambda d: d["listed"]["registry"].update(page_size=0)),
    "page cap a bool": mutated(lambda d: d["listed"]["registry"].update(page_cap=True)),
}


@pytest.mark.parametrize("raw", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_reference_file_is_shape_mismatch_for_every_rule(monkeypatch, raw):
    monkeypatch.setattr(tc, "read_reference_bytes", lambda: raw)
    report = check("mcp-server-fetc", "pypi")
    assert report.coverage.ran == ()
    assert skipped(report) == {
        r: (SkipReason.SHAPE_MISMATCH, SkipDetail.REFERENCE_FILE_MALFORMED)
        for r in ts.RULE_IDS
    }
    assert report.assessment is Assessment.NO_FINDINGS_DETECTED
    assert report.data_sources == ()


def test_unreadable_reference_file_is_not_determinable(monkeypatch):
    def unreadable():
        raise FileNotFoundError("reference_names.json")

    monkeypatch.setattr(tc, "read_reference_bytes", unreadable)
    report = check("mcp-server-fetc", "pypi")
    assert set(skipped(report).values()) == {
        (SkipReason.NOT_DETERMINABLE, SkipDetail.REFERENCE_FILE_UNREADABLE)
    }


def test_loader_crash_is_rule_error(monkeypatch):
    def crash(raw):
        raise RuntimeError("bug")

    monkeypatch.setattr(tc, "parse_reference_names", crash)
    report = check("mcp-server-fetc", "pypi")
    assert set(skipped(report).values()) == {(SkipReason.RULE_ERROR, None)}


def test_rule_crash_is_rule_error_and_others_still_run(monkeypatch):
    def crash(name, refs):
        raise RuntimeError("bug")

    monkeypatch.setattr(ts, "ts003_edit_distance", crash)
    report = check("mcp-server-fetc", "pypi", today=fresh())
    assert skipped(report)["TS003"] == (SkipReason.RULE_ERROR, None)
    assert "TS001" in report.coverage.ran


def test_malformed_rule_data_is_shape_mismatch(monkeypatch):
    def bad():
        raise ts.RuleDataError("confusables.yaml: malformed")

    monkeypatch.setattr(ts, "load_confusables", bad)
    report = check("mcp-server-fetc", "pypi", today=fresh())
    assert skipped(report)["TS002"] == (SkipReason.SHAPE_MISMATCH, None)
    assert "TS003" in report.coverage.ran


# --- evidence never echoes more than three reference names


def synthetic(names: list[str]) -> bytes:
    doc = {
        "curated": [
            {
                "checked_at": "2026-11-02",
                "ecosystem": "pypi",
                "name": n,
                "source": "test",
            }
            for n in names
        ],
        "generated_at": "2026-11-02",
        "listed": {},
        "sources": [
            {
                "id": "test",
                "name": "test",
                "type": "dependency",
                "url": "https://example.com/",
            }
        ],
    }
    return json.dumps(doc, sort_keys=True).encode()


def test_evidence_never_echoes_more_than_three_reference_names(monkeypatch):
    # Each of these is similar to the input by a different rule.
    names = [
        "MCP-Widget",
        "mcp-widgets",
        "mcp-widget-server",
        "widget-mcp",
        "mcp-widgel",
    ]
    monkeypatch.setattr(tc, "read_reference_bytes", lambda: synthetic(names))
    report = check("mcp-widget", "pypi", today=date(2026, 11, 3))
    rendered = json.dumps(report.to_dict())
    echoed = {n for n in names if re.search(rf"\b{re.escape(n)}\b", rendered)}
    assert 1 <= len(echoed) <= tc.MAX_REFERENCE_NAMES
    assert any("further match" in n for n in report.notes)


def test_evidence_names_source_and_method_and_is_capped():
    report = check("mcp-server-fetc", "pypi", today=fresh())
    (f,) = [f for f in report.findings if f.rule_id == "TS003"]
    text = f.to_dict()["evidence"]["untrusted_text"]
    assert (
        text == "source reference-server; edit distance 1; similar to mcp-server-fetch"
    )
    assert len(text) <= 120


def test_listed_not_curated_evidence_says_so():
    ref = ts.Reference(
        ts.normalize("io.github.zqvex-lab/weather-server", "registry"),
        "mcp-registry-crawl",
        ts.LISTED_NOT_CURATED,
    )
    (match,) = ts.ts006_scope(
        ts.normalize("io.github.zqvex-labs/weather-server", "registry"),
        [ref],
        ts.load_confusables(),
    )
    assert "listed-not-curated (MCP Registry listing, not reviewed)" in (
        match.finding.evidence
    )
    assert match.finding.location == "name.namespace"


def test_reference_names_differing_only_in_case_do_not_match_each_other(monkeypatch):
    names = ["io.github.example/Weather-Server", "io.github.example/weather-server"]

    def add_case_variant(doc):
        listed = doc["listed"]["registry"]
        listed["names"] = sorted({*listed["names"], *names})

    monkeypatch.setattr(tc, "read_reference_bytes", lambda: mutated(add_case_variant))
    registry = tc.parse_reference_names(tc.read_reference_bytes()).by_ecosystem[
        "registry"
    ]
    assert set(names) <= {r.name.raw for r in registry}
    for name in names:
        report = check(name, "registry", today=fresh())
        assert "TS001" not in rule_ids(report)
        assert report.findings == ()
        assert tc.REFERENCE_ENTRY_NOTE in report.notes


def test_registry_names_are_lowercased_in_both_parts():
    name = ts.normalize("IO.GitHub.Example/Weather", "registry")
    assert (name.scope, name.part) == ("io.github.example", "weather")
    ref = ts.Reference(
        ts.normalize("io.github.example/weather", "registry"),
        "s",
        ts.LISTED_NOT_CURATED,
    )
    # Untuned, so the case difference is visible; tuned, C and A leave it unreported.
    assert [
        m.finding.rule_id for m in ts.ts001_normalized_equal(name, [ref], ts.UNTUNED)
    ] == ["TS001"]
    assert ts.ts001_normalized_equal(name, [ref]) == []


# --- precision: every reference name against the rest of the list


def run_against_rest(ecosystem: str) -> list[tuple[str, str, str, str]]:
    """(name, rule, location, matched reference) for every pair that fires."""
    refs = loaded().by_ecosystem[ecosystem]
    pairs = []
    for ref in refs:
        rest = [r for r in refs if r is not ref]
        matches, _ = tc.run_rules(ref.name, rest)
        pairs += [
            (ref.name.raw, m.finding.rule_id, m.finding.location, m.reference.name.raw)
            for m in matches
        ]
    return pairs


def test_precision_reference_names_against_each_other(capsys):
    lines = []
    for ecosystem in ts.ECOSYSTEMS:
        count = len(loaded().by_ecosystem[ecosystem])
        pairs = run_against_rest(ecosystem)
        lines.append(f"{ecosystem}: {count} reference names, {len(pairs)} firing pairs")
        lines += [
            f"  {rule} {name} ~ {other} ({loc})" for name, rule, loc, other in pairs
        ]
        if ecosystem == "registry":
            grouped: dict[str, Counter] = defaultdict(Counter)
            for _, rule, loc, _ in pairs:
                part = {"name.namespace": "namespace", "name.name": "name"}.get(
                    loc, "whole"
                )
                grouped[part][rule] += 1
            for part in ("namespace", "name", "whole"):
                counts = ", ".join(f"{r}={grouped[part][r]}" for r in ts.RULE_IDS)
                lines.append(f"  registry tier, match on {part}: {counts}")
    with capsys.disabled():
        print("\n" + "\n".join(lines))


# --- rule data, spec table, edit distance


@pytest.mark.parametrize(
    "filename,key",
    [
        ("confusables.yaml", "mappings"),
        ("typosquat_affixes.yaml", "prefixes"),
        ("typosquat_affixes.yaml", "suffixes"),
    ],
)
def test_every_rule_data_entry_has_a_comment(filename, key):
    data = yaml.safe_load((DATA / filename).read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data[key]
    assert all(isinstance(e.get("comment"), str) and e["comment"] for e in data[key])


def test_affixes_match_spec():
    affixes = ts.load_affixes()
    assert set(affixes.prefixes) | set(affixes.suffixes) == {
        "-mcp",
        "mcp-",
        "-server",
        "-official",
        "-py",
        "-js",
    }


def test_rule_table_matches_spec():
    rows = re.findall(
        r"^\| (TS\d{3}) \|[^|]+\| (\w+) \| (\w+) \| (MCP\d{2}) \|$",
        SPEC.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert [r[0] for r in rows] == list(ts.RULE_IDS)
    for rule_id, severity, confidence, owasp in rows:
        rule = ts._RULES[rule_id]
        assert (rule.severity.value, rule.confidence.value) == (severity, confidence)
        assert ts.RULE_OWASP[rule_id] == (f"{owasp}:2025",)
        assert ts.RULE_OWASP[rule_id][0] in OWASP_MCP_TOP_10


def brute_osa(a: str, b: str) -> int:
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


WORDS = [
    "",
    "a",
    "ab",
    "ba",
    "abc",
    "acb",
    "fetch",
    "fecth",
    "fetc",
    "tefch",
    "xyz",
    "httpx",
]


@pytest.mark.parametrize("limit", [0, 1, 2, 3])
def test_bounded_edit_distance_agrees_with_full_table(limit):
    for a in WORDS:
        for b in WORDS:
            full = brute_osa(a, b)
            assert ts.edit_distance(a, b, limit) == (full if full <= limit else None)


def test_edit_distance_exits_early_on_length():
    assert ts.edit_distance("a" * 10_000, "b", 2) is None


# --- module boundaries


HTTP_MODULES = ("httpx", "requests", "urllib", "http", "aiohttp", "socket", "ssl")


def test_detector_imports_no_http_client():
    source = (ROOT / "src/mcp_supply_audit/detectors/typosquat.py").read_text(
        encoding="utf-8"
    )
    imported = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    bad = [
        m
        for m in imported
        if m.split(".")[0] in HTTP_MODULES or m.startswith("mcp_supply_audit.clients")
    ]
    assert imported and bad == []


def test_build_script_not_imported_by_src():
    for path in (ROOT / "src").rglob("*.py"):
        assert "build_reference_names" not in path.read_text(encoding="utf-8")


# --- build script (dev-only; no network)


def load_script():
    spec = importlib.util.spec_from_file_location(
        "build_reference_names", ROOT / "scripts/build_reference_names.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CURATED_ENTRY = {
    "name": "mcp-server-fetch",
    "ecosystem": "pypi",
    "source_type": "reference-server",
    "source_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
    "checked_at": "2026-11-02",
}


def curated_text(*entries) -> str:
    return yaml.safe_dump({"version": 1, "entries": list(entries)})


@pytest.mark.parametrize("url", [None, "", "http://example.com/", "github.com/x"])
def test_script_refuses_entries_without_source_url(url):
    build = load_script()
    entry = dict(CURATED_ENTRY)
    if url is None:
        entry.pop("source_url")
    else:
        entry["source_url"] = url
    with pytest.raises(build.CurationError, match=r"entries\[1\]: no https source_url"):
        build.load_curated(curated_text(CURATED_ENTRY, entry))


def test_packaged_reference_file_shape():
    # The only test that reads the generated file; skipped until it has been built.
    packaged = DATA / "reference_names.json"
    if not packaged.is_file():
        pytest.skip("data/reference_names.json has not been generated")
    raw = packaged.read_bytes()
    parsed = tc.parse_reference_names(raw)
    assert parsed.entry_count > 0
    assert raw.decode("ascii") == load_script().render(json.loads(raw))


def page(names, cursor=None, description="hostile text"):
    servers = [{"server": {"name": n, "description": description}} for n in names]
    metadata = {"count": len(names), **({"nextCursor": cursor} if cursor else {})}
    return json.dumps({"servers": servers, "metadata": metadata}).encode()


def test_crawl_keeps_valid_names_only_and_follows_returned_cursors():
    build = load_script()
    pages = {
        None: page(["io.github.a/one", "../bad", f"io.github.b/tw{CYRILLIC_A}"], "c1"),
        "c1": page(["io.github.c/three", "io.github.a/one"]),
    }
    sent, sleeps = [], []

    def fetch(params):
        sent.append(dict(params))
        return pages[params.get("cursor")]

    result = build.crawl(fetch, sleep=sleeps.append)
    assert result.names == ["io.github.a/one", "io.github.c/three"]
    assert (result.invalid, result.partial, result.pages_fetched) == (2, False, 2)
    assert result.stop_reason == build.STOP_NO_CURSOR
    assert [p.get("cursor") for p in sent] == [None, "c1"]
    assert all(p["limit"] == str(build.PAGE_SIZE) for p in sent)
    assert all(p["version"] == "latest" for p in sent)
    assert sleeps == [build.DELAY_SECONDS]


def test_crawl_aborts_on_repeated_cursor():
    build = load_script()
    with pytest.raises(build.CrawlRepeatedCursor) as info:
        build.crawl(lambda p: page(["io.github.a/one"], "again"), sleep=lambda s: None)
    assert info.value.pages_fetched == 2


def endless_pages(calls):
    def fetch(params):
        calls.append(params)
        return page([f"io.github.a/name{len(calls)}"], f"c{len(calls)}")

    return fetch


def test_capped_crawl_is_partial_and_records_pages_fetched():
    build = load_script()
    calls = []
    result = build.crawl(endless_pages(calls), max_pages=3, sleep=lambda s: None)
    assert len(calls) == 3
    assert (result.partial, result.pages_fetched, result.page_cap) == (True, 3, 3)
    doc = build.build_document([CURATED_ENTRY], result, date(2026, 11, 3))
    assert doc["listed"]["registry"]["partial"] is True
    assert doc["listed"]["registry"]["pages_fetched"] == 3
    assert doc["listed"]["registry"]["page_cap"] == 3
    assert doc["listed"]["registry"]["page_size"] == build.PAGE_SIZE


def test_exhausted_cursor_is_not_partial():
    build = load_script()
    result = build.crawl(lambda p: page(["io.github.a/one"]), sleep=lambda s: None)
    doc = build.build_document([CURATED_ENTRY], result, date(2026, 11, 3))
    assert doc["listed"]["registry"]["partial"] is False
    assert doc["listed"]["registry"]["pages_fetched"] == 1
    assert tc.parse_reference_names(build.render(doc).encode()).partial is False


def crawl_result(build, names, *, pages=1, cap=100):
    stop = build.STOP_PAGE_CAP if pages == cap else build.STOP_NO_CURSOR
    return build.CrawlResult(
        names=names, invalid=0, pages_fetched=pages, page_cap=cap, stop_reason=stop
    )


def test_compact_file_round_trips_through_the_loader():
    build = load_script()
    crawled = crawl_result(build, ["io.github.a/one", "io.github.b/two"])
    doc = build.build_document([CURATED_ENTRY], crawled, date(2026, 11, 3))
    (listed,) = [s for s in doc["sources"] if s["id"] == build.CRAWL_SOURCE]
    assert (listed["type"], listed["url"]) == (
        "listed-not-curated",
        build.REGISTRY_LIST_URL,
    )
    assert doc["listed"]["registry"]["source"] == build.CRAWL_SOURCE
    parsed = tc.parse_reference_names(build.render(doc).encode())
    assert [(r.name.raw, r.source_type) for r in parsed.by_ecosystem["registry"]] == [
        ("io.github.a/one", "listed-not-curated"),
        ("io.github.b/two", "listed-not-curated"),
    ]
    assert [r.name.raw for r in parsed.by_ecosystem["pypi"]] == ["mcp-server-fetch"]
    assert parsed.entry_count == 3
    assert parsed.generated_at == date(2026, 11, 3)


def test_fixture_is_in_the_rendered_format():
    raw = FIXTURE.read_bytes()
    assert raw.decode("ascii") == load_script().render(json.loads(raw))
    counts = {e: len(refs) for e, refs in loaded().by_ecosystem.items()}
    assert all(counts.values()) and sum(counts.values()) == loaded().entry_count


def test_crawled_name_matching_a_curated_one_is_kept_once():
    build = load_script()
    curated = dict(
        CURATED_ENTRY,
        name="io.github.a/one",
        ecosystem="registry",
        source_url="https://example.com/one",
    )
    doc = build.build_document(
        [curated],
        crawl_result(build, ["io.github.a/one", "io.github.b/two"]),
        date.today(),
    )
    assert doc["listed"]["registry"]["names"] == ["io.github.b/two"]
    parsed = tc.parse_reference_names(build.render(doc).encode())
    assert [r.name.raw for r in parsed.by_ecosystem["registry"]] == [
        "io.github.a/one",
        "io.github.b/two",
    ]


def test_rendered_file_stays_ascii():
    build = load_script()
    # build_document does not validate; render must still escape a non-ASCII name.
    crawled = crawl_result(build, [f"io.github.a/n{CYRILLIC_A}me"])
    rendered = build.render(
        build.build_document([CURATED_ENTRY], crawled, date(2026, 11, 3))
    )
    assert rendered.isascii()
    assert "\\u0430" in rendered


# --- the partial note


def partial_file(pages: int, cap: int) -> bytes:
    def change(doc):
        doc["listed"]["registry"].update(
            pages_fetched=pages, page_cap=cap, partial=pages == cap
        )

    return mutated(change)


def test_partial_note_appears_only_when_partial(monkeypatch):
    monkeypatch.setattr(tc, "read_reference_bytes", lambda: partial_file(3, 3))
    report = check("io.github.exampl/weather-server", "registry", today=fresh())
    assert report.notes == (
        "The registry reference list is partial: 5 entries from the first 3 pages.",
    )
    assert report.notes == (tc.partial_note(5, 3),)
    assert report.to_dict()["data_sources"][0]["partial"] is True
    assert report.assessment is Assessment.FINDINGS_PRESENT

    monkeypatch.setattr(tc, "read_reference_bytes", lambda: partial_file(3, 100))
    report = check("io.github.exampl/weather-server", "registry", today=fresh())
    assert report.notes == ()
    assert report.to_dict()["data_sources"][0]["partial"] is False


@pytest.mark.parametrize(
    "name,ecosystem",
    [("mcp-server-fetc", "pypi"), ("@modelcontextprotocol/server-memry", "npm")],
)
def test_partial_note_never_on_pypi_or_npm_reports(monkeypatch, name, ecosystem):
    monkeypatch.setattr(tc, "read_reference_bytes", lambda: partial_file(3, 3))
    report = check(name, ecosystem, today=fresh())
    assert report.notes == ()
    assert report.assessment is Assessment.FINDINGS_PRESENT
    assert report.to_dict()["data_sources"][0]["partial"] is True


def test_partial_note_wording_is_in_the_spec():
    assert tc.partial_note(5, 3).replace("5", "N").replace("3", "P") in (
        SPEC.read_text(encoding="utf-8")
    )


# --- the build script end to end (respx; no network, no real output file)

CRAWL_ROUTE = "https://registry.modelcontextprotocol.io/v0/servers"


@pytest.fixture
def script_paths(tmp_path, monkeypatch):
    build = load_script()
    curated = tmp_path / "curated_names.yaml"
    curated.write_text(curated_text(CURATED_ENTRY), encoding="utf-8")
    monkeypatch.setattr(build, "CURATED", curated)
    monkeypatch.setattr(build, "OUTPUT", tmp_path / "reference_names.json")
    return build


def ticking_clock(step: float):
    now = [0.0]

    def clock():
        now[0] += step
        return now[0]

    return clock


def test_two_page_crawl_logs_progress_to_stderr(script_paths, capsys):
    build = script_paths
    with respx.mock() as router:
        route = router.get(CRAWL_ROUTE).mock(
            side_effect=[
                httpx.Response(200, content=page(["io.github.a/one"], "c1")),
                httpx.Response(200, content=page(["io.github.b/two"])),
            ]
        )
        code = build.main(
            ["--crawl", "--max-pages", "5"],
            sleep=lambda s: None,
            clock=ticking_clock(0.5),
        )
    assert code == 0
    assert [dict(c.request.url.params) for c in route.calls] == [
        {"limit": "100", "version": "latest"},
        {"limit": "100", "version": "latest", "cursor": "c1"},
    ]
    out, err = capsys.readouterr()
    assert out == ""
    lines = err.splitlines()
    assert lines[0] == (
        f"crawl: page cap {build.MAX_PAGES} (default), --max-pages 5, "
        "page size 100, delay 1 s, time limit 20 min"
    )
    assert re.fullmatch(
        r"crawl: page 1: 1 names so far, request \d+\.\d\d s, elapsed \d+\.\d s",
        lines[1],
    )
    assert lines[2].startswith("crawl: page 2: 2 names so far, request ")
    assert f"{2:6d}  {build.CRAWL_SOURCE}" in lines
    assert f"wrote 3 entries to {build.OUTPUT}" in lines
    assert lines[-1] == f"crawl stopped after 2 pages: {build.STOP_NO_CURSOR}"
    written = json.loads(build.OUTPUT.read_text(encoding="ascii"))
    assert written["listed"]["registry"]["partial"] is False
    assert written["listed"]["registry"]["pages_fetched"] == 2


def test_page_cap_writes_a_partial_file(script_paths, capsys):
    build = script_paths
    with respx.mock() as router:
        router.get(CRAWL_ROUTE).mock(
            return_value=httpx.Response(200, content=page(["io.github.a/one"], "c1"))
        )
        code = build.main(
            ["--crawl", "--max-pages", "1"],
            sleep=lambda s: None,
            clock=ticking_clock(1),
        )
    assert code == 0
    listed = json.loads(build.OUTPUT.read_text(encoding="ascii"))["listed"]["registry"]
    assert (listed["partial"], listed["pages_fetched"], listed["page_cap"]) == (
        True,
        1,
        1,
    )
    assert capsys.readouterr().err.splitlines()[-1] == (
        f"crawl stopped after 1 pages: {build.STOP_PAGE_CAP}"
    )


def test_time_limit_aborts_without_writing_a_file(script_paths, capsys):
    build = script_paths
    with respx.mock() as router:
        route = router.get(CRAWL_ROUTE).mock(
            return_value=httpx.Response(200, content=page(["io.github.a/one"], "c1"))
        )
        # Each clock reading is 30 s later, so the limit of 1 minute is hit mid-crawl.
        code = build.main(
            ["--crawl", "--time-limit-minutes", "1"],
            sleep=lambda s: None,
            clock=ticking_clock(30),
        )
    assert code == 3
    assert route.call_count >= 1
    assert not build.OUTPUT.exists()
    err = capsys.readouterr().err
    assert "the 1-minute time limit was reached" in err
    assert "nothing written" in err


def test_repeated_cursor_aborts_and_leaves_the_existing_file(script_paths, capsys):
    build = script_paths
    build.OUTPUT.write_text("previous file\n", encoding="ascii")
    with respx.mock() as router:
        route = router.get(CRAWL_ROUTE).mock(
            return_value=httpx.Response(200, content=page(["io.github.a/one"], "c1"))
        )
        code = build.main(["--crawl"], sleep=lambda s: None, clock=ticking_clock(0.5))
    assert code == 4
    assert route.call_count == 2
    assert build.OUTPUT.read_text(encoding="ascii") == "previous file\n"
    out, err = capsys.readouterr()
    assert out == ""
    assert err.splitlines()[-1] == (
        f"crawl stopped after 2 pages: {build.STOP_REPEATED_CURSOR}; nothing written"
    )


@pytest.mark.parametrize("argv", [["--max-pages", "0"], ["--time-limit-minutes", "-1"]])
def test_limits_must_be_positive(script_paths, argv):
    with pytest.raises(SystemExit):
        script_paths.main(argv)


# --- registry tuning A-D (docs/rules-typosquat.md); invented zqvex-* names only

ZQ_HOST = "io.github.zqvex-hosting"
ZQ_LAB = "io.github.zqvex-lab"


def zq_refs(*names: str) -> list[ts.Reference]:
    return [
        ts.Reference(
            ts.normalize(n, "registry"), "mcp-registry-crawl", ts.LISTED_NOT_CURATED
        )
        for n in names
    ]


def zq_run(name: str, *refs: str, tuning=ts.REGISTRY_TUNING):
    return tc.run_rules(ts.normalize(name, "registry"), zq_refs(*refs), tuning)


def zq_rules(name: str, *refs: str, tuning=ts.REGISTRY_TUNING) -> set[str]:
    return {m.finding.rule_id for m in zq_run(name, *refs, tuning=tuning)[0]}


@pytest.fixture
def zq_platform(monkeypatch):
    monkeypatch.setattr(ts, "load_platform_namespaces", lambda: frozenset({ZQ_HOST}))


@pytest.mark.parametrize(
    "name,ref,rule",
    [
        (f"{ZQ_LAB}/gadget-hubs", f"{ZQ_LAB}/gadget-hub", "TS003"),
        (f"{ZQ_LAB}/gadget-hub-mcp", f"{ZQ_LAB}/gadget-hub", "TS004"),
        (f"{ZQ_LAB}/gadget-hub", f"{ZQ_LAB}/Gadget-Hub", "TS001"),
        ("io.github.ZQVEX-LAB/gadget-hubs", f"{ZQ_LAB}/gadget-hub", "TS003"),
    ],
)
def test_a_same_namespace_pair_is_exempt(zq_platform, name, ref, rule):
    assert rule in zq_rules(name, ref, tuning=ts.UNTUNED)
    assert rule not in zq_rules(name, ref)


@pytest.mark.parametrize(
    "name,ref,rule",
    [
        (f"{ZQ_HOST}/zqb-widget", f"{ZQ_HOST}/zqa-widget", "TS003"),
        (f"{ZQ_HOST}/mcp-widget-tools", f"{ZQ_HOST}/widget-tools", "TS004"),
        (f"{ZQ_HOST}/Alice-Widget", f"{ZQ_HOST}/alice-widget", "TS001"),
        (f"{ZQ_HOST.upper()}/zqb-widget", f"{ZQ_HOST}/zqa-widget", "TS003"),
    ],
)
def test_a_platform_namespace_is_not_exempt(zq_platform, name, ref, rule):
    assert rule in zq_rules(name, ref)


@pytest.mark.parametrize(
    "name,ref,rule",
    [
        (f"{ZQ_HOST}/alice-widgets", f"{ZQ_HOST}/alice-widget", "TS003"),
        (f"{ZQ_HOST}/alice-widget-mcp", f"{ZQ_HOST}/alice-widget", "TS004"),
        (f"{ZQ_HOST.upper()}/Alice-Widgets", f"{ZQ_HOST}/alice-widget", "TS003"),
    ],
)
def test_e_equal_owner_tokens_on_a_platform_are_exempt(zq_platform, name, ref, rule):
    assert rule in zq_rules(name, ref, tuning=ts.UNTUNED)
    assert rule not in zq_rules(name, ref)


def test_e_does_not_touch_ts001(zq_platform):
    assert "TS001" in zq_rules(f"{ZQ_HOST}/Alice-Widget", f"{ZQ_HOST}/alice-widget")


def test_e_owner_token_cannot_tell_foo_bar_from_foo():
    # Owner zqvex-ann with server tool, and owner zqvex with server ann-tools: one token.
    assert ts.owner_token("zqvex-ann-tool") == ts.owner_token("zqvex-ann-tools")
    assert ts.same_owner_token(
        ts.normalize(f"{ZQ_HOST}/zqvex-ann-tool", "registry"),
        ts.normalize(f"{ZQ_HOST}/zqvex-ann-tools", "registry"),
    )


def test_b_ts005_is_not_used_on_the_registry_tier(zq_platform):
    matches, coverage = zq_run(f"{ZQ_HOST}/sync-data", f"{ZQ_HOST}/data-sync")
    assert "TS005" not in {m.finding.rule_id for m in matches}
    assert skip_of(coverage, "TS005") == (
        SkipReason.NOT_APPLICABLE,
        SkipDetail.NOT_USED_FOR_REGISTRY,
    )
    assert "TS005" in zq_rules(
        f"{ZQ_HOST}/sync-data", f"{ZQ_HOST}/data-sync", tuning=ts.UNTUNED
    )


def skip_of(coverage, rule_id):
    return {s.check: (s.reason, s.detail) for s in coverage.skipped}.get(rule_id)


@pytest.mark.parametrize(
    "name,ref",
    [
        ("io.github.ZQVEX-LAB/gadget-hub", f"{ZQ_LAB}/gadget-hub"),
        (ZQ_HOST.upper() + "/alice-widget", f"{ZQ_HOST}/alice-widget"),
    ],
)
def test_c_case_only_namespace_never_produces_a_finding(zq_platform, name, ref):
    assert zq_rules(name, ref, tuning=ts.UNTUNED) == {"TS001"}
    assert zq_rules(name, ref) == set()


def test_d_ts006_keeps_distance_1_and_is_low_low():
    (m,) = zq_run("io.github.zqvex-labs/gadget-hub", f"{ZQ_LAB}/gadget-hub")[0]
    assert m.finding.rule_id == "TS006"
    assert (m.finding.severity.value, m.finding.confidence.value) == ("low", "low")
    assert "similar to io.github.zqvex-lab/gadget-hub" in m.finding.evidence


@pytest.mark.parametrize(
    "name,ref",
    [
        ("com.zqvexlabxy/gadget-hub", "com.zqvexlab/gadget-hub"),
        # one side io.github., the other not (github -> gitlab is two edits)
        ("io.github.zqvex/relay-hub", "io.gitlab.zqvex/relay-hub"),
    ],
)
def test_d_distance_2_is_dropped_unless_both_are_io_github(name, ref):
    assert ts.edit_distance(name.split("/")[0], ref.split("/")[0], 2) == 2
    assert "TS006" in zq_rules(name, ref, tuning=ts.UNTUNED)
    assert "TS006" not in zq_rules(name, ref)


def test_d_distance_2_is_kept_when_both_are_io_github():
    (m,) = zq_run("io.github.zqvex-labxy/gadget-hub", f"{ZQ_LAB}/gadget-hub")[0]
    assert (m.finding.rule_id, m.finding.severity.value) == ("TS006", "low")
    assert "scope edit distance 2" in m.finding.evidence


@pytest.mark.parametrize(
    "name,ref,method",
    [
        (
            "io.github.zqvexlab/gadget-hub",
            f"{ZQ_LAB}/gadget-hub",
            "scope edit distance 1",
        ),
        (
            f"{ZQ_LAB}/gadget-hub",
            "io.github.zqvexlab/gadget-hub",
            "scope edit distance 1",
        ),
        ("com.zqvexnet/relay-hub", "io.zqvexnet/relay-hub", "first label"),
        ("dev.zqvexnet/relay-hub", "io.zqvexnet/relay-hub", "first label"),
        ("io.zqvexrn/relay-node", "io.zqvexm/relay-node", "lookalike"),
    ],
)
def test_d_hyphen_tld_variant_and_lookalike_fire(name, ref, method):
    (m,) = zq_run(name, ref)[0]
    assert m.finding.rule_id == "TS006"
    assert method in m.finding.evidence


@pytest.mark.parametrize("ecosystem", ["pypi", "npm"])
def test_pypi_and_npm_are_unchanged_by_the_registry_tuning(monkeypatch, ecosystem):
    def no_platform_file():
        raise AssertionError("pypi and npm must not read the platform file")

    monkeypatch.setattr(ts, "load_platform_namespaces", no_platform_file)
    refs = loaded().by_ecosystem[ecosystem]
    names = [r.name.raw for r in refs]
    mutations = (
        {n[:-1] for n in names}
        | {n + "-mcp" for n in names}
        | {"-".join(reversed(n.split("-"))) for n in names}
    )
    if ecosystem == "npm":
        mutations |= {"@" + n[2:] for n in names} | {n.replace("o", "0") for n in names}
    for raw in sorted(mutations):
        try:
            name = ts.normalize(tc._VALIDATORS[ecosystem](raw), ecosystem)
        except ToolError:
            continue
        tuned = tc.run_rules(name, refs)
        untuned = tc.run_rules(name, refs, ts.UNTUNED)
        assert tuned == untuned, raw


def test_malformed_platform_file_fails_only_the_registry_rules_that_read_it(
    monkeypatch,
):
    def broken():
        raise tc.RuleDataError("bad")

    monkeypatch.setattr(ts, "load_platform_namespaces", broken)
    _, coverage = zq_run(f"{ZQ_LAB}/gadget-hubs", f"{ZQ_LAB}/gadget-hub")
    shape = {s.check for s in coverage.skipped if s.reason is SkipReason.SHAPE_MISMATCH}
    assert shape == {"TS001", "TS003", "TS004"}
    assert {"TS002", "TS006"} <= set(coverage.ran)
    report = check("mcp-server-fetc", "pypi", today=fresh())
    assert "TS003" in rule_ids(report)


def platform_yaml(tmp_path, monkeypatch, body: str):
    import mcp_supply_audit.detectors.typosquat as module

    def fake(filename):
        assert filename == "platform_namespaces.yaml"
        return yaml.safe_load(body)

    monkeypatch.setattr(module, "load_rule_data", fake)
    ts.load_platform_namespaces.cache_clear()


def test_platform_file_loads_and_lowercases(tmp_path, monkeypatch):
    platform_yaml(
        tmp_path,
        monkeypatch,
        f"version: 1\nnamespaces:\n  - namespace: {ZQ_HOST.upper()}\n"
        '    checked_at: "2026-11-04"\n    evidence: [invented test entry]\n',
    )
    try:
        assert ts.load_platform_namespaces() == frozenset({ZQ_HOST})
    finally:
        ts.load_platform_namespaces.cache_clear()


@pytest.mark.parametrize(
    "entry",
    [
        f'namespace: {ZQ_HOST}\n    checked_at: "2026-11-04"',
        f'namespace: {ZQ_HOST}\n    checked_at: "2026-11-04"\n    evidence: []',
        f"namespace: {ZQ_HOST}\n    evidence: [x]",
        f"namespace: {ZQ_HOST}\n    checked_at: 2026-11-04\n    evidence: [x]",
        f'namespace: {ZQ_HOST}/x\n    checked_at: "2026-11-04"\n    evidence: [x]',
        'checked_at: "2026-11-04"\n    evidence: [x]',
    ],
)
def test_platform_entry_without_evidence_or_date_is_refused(
    tmp_path, monkeypatch, entry
):
    platform_yaml(tmp_path, monkeypatch, f"version: 1\nnamespaces:\n  - {entry}\n")
    try:
        with pytest.raises(tc.RuleDataError):
            ts.load_platform_namespaces()
    finally:
        ts.load_platform_namespaces.cache_clear()


def test_shipped_platform_file_is_well_formed():
    assert ts.load_platform_namespaces()


def test_registry_tuning_constants_are_in_the_spec():
    spec = SPEC.read_text(encoding="utf-8")
    for constant in (
        "REGISTRY_EXEMPT_SAME_NAMESPACE",
        "REGISTRY_DROP_TS005",
        "REGISTRY_IGNORE_NAMESPACE_CASE",
        "REGISTRY_TS006_MAX_DISTANCE",
        "REGISTRY_TS006_TLD_VARIANT",
        "REGISTRY_TS006_SEVERITY",
        "REGISTRY_TS006_CONFIDENCE",
        "REGISTRY_TS006_DISTANCE_2_PREFIX",
        "REGISTRY_PLATFORM_OWNER_TOKEN",
    ):
        assert f"`{constant}`" in spec
