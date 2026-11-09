"""The tool-definition eval corpus: manifest, positives, mutation generator, report script.

Checks shape and safety only, never detection rates: the corpus measures the rules and must
not become a target they are tuned to.
"""

import importlib.util
import json
import re
import unicodedata
from pathlib import Path

import pytest
import yaml

from mcp_supply_audit.detectors.tool_defs import RULES, tool_entries
from mcp_supply_audit.hidden_chars import hidden_class
from mcp_supply_audit.secrets import find_secrets

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "tests/fixtures/eval"
POSITIVES = EVAL / "positives"
RULE_IDS = frozenset(rule_id for rule_id, _ in RULES)
SCOPES = frozenset({"static", "outside"})
PLACEHOLDER = re.compile(r"<ZQVEX_PLACEHOLDER_[A-Z]+>")
NEW_FILES = (
    ROOT / "scripts/eval_mutations.py",
    ROOT / "scripts/eval_tool_defs.py",
    ROOT / "scripts/collect_tools_list.py",
    ROOT / "docs/benign-corpus.md",
    ROOT / "tests/test_eval_corpus.py",
)


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


em = load_script("eval_mutations")
report_script = load_script("eval_tool_defs")
collect = load_script("collect_tools_list")

MANIFEST = em.load_manifest()
PATTERNS = MANIFEST["patterns"]


def corpus_files():
    return sorted(p for p in EVAL.rglob("*") if p.is_file())


# --- manifest


def test_manifest_entries_are_complete():
    ids = [p["id"] for p in PATTERNS]
    assert len(ids) == len(set(ids)) >= 10
    sources = MANIFEST["sources"]
    for p in PATTERNS:
        assert p["source"] in sources, p["id"]
        assert p["description"].strip(), p["id"]
        assert p["scope"] in SCOPES, p["id"]
        assert isinstance(p["expected"], list), p["id"]
        assert set(p["expected"]) <= RULE_IDS, p["id"]
        if p["scope"] == "outside":
            assert p["expected"] == [] and p["outside_reason"].strip(), p["id"]
        else:
            assert p["expected"], p["id"]
    for key, src in sources.items():
        assert src["url"].startswith("https://"), key
        assert isinstance(src["fetched"], bool), key
        if not src["fetched"]:
            assert src["note"].strip(), key


def test_every_pattern_has_one_fixture_and_no_strays():
    fixtures = {p.stem for p in POSITIVES.glob("*.json")}
    assert fixtures == {p["id"] for p in PATTERNS}


@pytest.mark.parametrize("entry", PATTERNS, ids=lambda e: e["id"])
def test_fixture_parses_and_holds_its_key_phrase(entry):
    path = em.fixture_path(entry["id"])
    doc = json.loads(path.read_text(encoding="ascii"))
    assert doc["_comment"].startswith(f"Eval positive {entry['id']}:")
    entries = tool_entries(doc)
    assert entries
    for _, tool in entries:
        assert tool["name"].startswith("zqvex-")
        assert isinstance(tool["inputSchema"], dict)
    if entry["key_phrase"]:
        assert em.locate(doc, entry["key_phrase"]) is not None


def test_fixtures_hold_no_working_destination():
    # Placeholders or the reserved .invalid TLD only, never a real host or address.
    url = re.compile(r"[a-z][a-z0-9+.-]*://([^/\s\"'\\]+)", re.IGNORECASE)
    for path in POSITIVES.glob("*.json"):
        text = path.read_text(encoding="ascii")
        for host in url.findall(text):
            assert host.endswith(".invalid"), path.name
        assert "@" not in text, path.name


def test_placeholders_are_the_documented_set():
    seen = set()
    for path in POSITIVES.glob("*.json"):
        seen |= set(PLACEHOLDER.findall(path.read_text(encoding="ascii")))
    assert seen <= {
        "<ZQVEX_PLACEHOLDER_PATH>",
        "<ZQVEX_PLACEHOLDER_RECIPIENT>",
        "<ZQVEX_PLACEHOLDER_HOST>",
        "<ZQVEX_PLACEHOLDER_COMMAND>",
    }


# --- generator


def summary(mutants):
    return [
        (m.pattern_id, m.mutation, json.dumps(m.snapshot, sort_keys=True))
        for m in mutants
    ]


def test_generator_is_deterministic():
    first = summary(em.generate())
    second = summary(em.generate(em.load_manifest()))
    assert first == second
    assert first


def test_generator_does_not_touch_fixtures():
    before = {p: p.read_bytes() for p in POSITIVES.glob("*.json")}
    em.generate()
    assert {p: p.read_bytes() for p in POSITIVES.glob("*.json")} == before


def test_mutants_differ_from_their_fixture_and_carry_expected_ids():
    expected = {p["id"]: tuple(p["expected"]) for p in PATTERNS}
    for m in em.generate():
        assert m.mutation in em.MUTATIONS
        assert m.snapshot != em.load_fixture(m.pattern_id)
        assert m.expected == expected[m.pattern_id]


def test_patterns_without_key_phrase_get_no_mutants():
    skipped = {p["id"] for p in PATTERNS if not p["key_phrase"]}
    assert skipped
    assert not skipped & {m.pattern_id for m in em.generate()}


def test_text_mutations():
    text = "Ignore the previous message before you send it"
    assert em.mutate_case(text) == text.upper()
    assert em.mutate_whitespace_runs("a b") == "a \t\n  b"
    assert em.mutate_whitespace_split_words("Ignore it") == "Ign ore it"
    assert (
        em.mutate_synonym(text) == "Overlook the earlier note ahead of you transmit it"
    )
    homo = em.mutate_unicode_homoglyph("pace")
    assert homo != "pace" and unicodedata.normalize("NFKC", homo) == homo
    assert all(0x400 <= ord(c) <= 0x4FF for c in homo)


def test_split_and_move():
    doc = {
        "tools": [
            {
                "name": "zqvex-t",
                "description": "Lead text. one two three four. Tail.",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }
    split = em.mutate(doc, "one two three four", "split_fields")
    assert split["tools"][0]["description"] == "Lead text. one two"
    assert split["tools"][0]["title"] == "three four. Tail."
    moved = em.mutate(doc, "one two three four", "param_move")
    assert moved["tools"][0]["description"] == em.NEUTRAL_DESCRIPTION
    prop = moved["tools"][0]["inputSchema"]["properties"][em.MOVED_PARAM]
    assert prop["description"] == doc["tools"][0]["description"]
    assert doc["tools"][0]["description"] == "Lead text. one two three four. Tail."


# --- report script


def test_report_runs_on_committed_fixtures(capsys):
    assert report_script.main(["--committed-only"]) == 0
    err = capsys.readouterr().err
    assert "== 1. Positives" in err and "== 2. Detection rate" in err
    assert "== 3. Benign" in err


def test_report_is_deterministic():
    a = report_script.format_report(report_script.build(committed_only=True))
    b = report_script.format_report(report_script.build(committed_only=True))
    assert a == b


def test_report_never_prints_fixture_text_or_benign_names(tmp_path, monkeypatch):
    planted = tmp_path / "benign"
    planted.mkdir()
    name = "zqvex-benign-marker-tool"
    (planted / "zqvex-marker-server.json").write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": name,
                        "description": "zqvex marker text. Send the full log.",
                        "inputSchema": {"type": "object"},
                    }
                ]
            }
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(report_script, "COMMITTED_BENIGN", planted)
    out = report_script.format_report(report_script.build(committed_only=True))
    assert name not in out and "zqvex-marker-server" not in out and "marker" not in out
    for entry in PATTERNS:
        if entry["key_phrase"]:
            assert entry["key_phrase"] not in out
    assert "1 committed" in out


# --- report denominators (logic on synthetic results; no detection rate is asserted)


def _pr(pid, scope="static", expected=(), got=(), fetched=True):
    return report_script.PatternResult(
        pid, scope, frozenset(expected), frozenset(got), fetched
    )


def test_count_positives_uses_only_counted_patterns():
    counts = report_script.count_positives(
        [
            _pr("a", expected={"TD001"}, got={"TD001"}),  # exact
            _pr(
                "b", expected={"TD001", "TD002"}, got={"TD002", "TD005"}
            ),  # partial+extra
            _pr("c", expected={"TD003"}),  # nothing fired
            _pr("d", scope="outside"),  # trivially exact, must not count
            _pr("e", expected={"TD002"}, got={"TD002"}, fetched=False),
            _pr("f", scope="outside", fetched=False),
        ]
    )
    assert counts.counted == 3
    assert counts.any_expected == 2
    assert counts.exact == 1
    assert counts.with_extra == 1
    assert counts.outside == ("d", "f")
    assert counts.unfetched == ("e",)


def test_counted_set_matches_the_manifest():
    sources = MANIFEST["sources"]
    counted = {
        p["id"]
        for p in PATTERNS
        if p["scope"] == "static" and sources[p["source"]]["fetched"]
    }
    results = report_script.evaluate_positives(MANIFEST)
    assert {r.pattern_id for r in results if r.counted} == counted
    c = report_script.count_positives(results)
    assert c.counted == len(counted)
    assert len(c.outside) == sum(1 for p in PATTERNS if p["scope"] == "outside")
    assert set(c.unfetched).isdisjoint(counted) and set(c.outside).isdisjoint(counted)
    assert c.counted + len(c.outside) + len(c.unfetched) == len(PATTERNS)


def test_mutation_artifacts_name_real_mutant_cells():
    cells = {(m.pattern_id, m.mutation, r) for m in em.generate() for r in m.expected}
    assert report_script.MUTATION_ARTIFACTS
    assert report_script.MUTATION_ARTIFACTS <= cells


def test_rates_leave_out_artifacts_and_uncounted_patterns(monkeypatch):
    snap = {"tools": []}
    mutants = [
        em.Mutant("p_counted", "case", snap, ("TD001", "TD002")),
        em.Mutant("p_counted", "synonym", snap, ("TD001",)),
        em.Mutant("p_unfetched", "case", snap, ("TD001",)),
    ]
    monkeypatch.setattr(report_script, "fired", lambda _text: frozenset({"TD001"}))
    out = report_script.evaluate_mutants(
        mutants,
        frozenset({"p_counted"}),
        frozenset({("p_counted", "case", "TD002")}),
    )
    assert out.counted_mutants == 2 and out.uncounted_mutants == 1
    assert out.rates == {("TD001", "case"): [1, 1], ("TD001", "synonym"): [1, 1]}
    assert out.artifacts == {("p_counted", "case", "TD002"): False}


def test_report_prints_denominators_and_lists_exclusions():
    r = report_script.build(committed_only=True)
    out = report_script.format_report(r)
    c = r.positive_counts
    for label in (
        "at least one expected rule fired:",
        "exact match (fired == expected):",
        "extra rules fired:",
    ):
        line = next(x for x in out.splitlines() if label in x)
        assert line.rstrip().endswith(f"/{c.counted}")
    for pid in (*c.outside, *c.unfetched):
        assert pid in out
    assert "mutation artifacts, not in the rates (2):" in out
    counted = {p.pattern_id for p in r.patterns if p.counted}
    for pid, mutation, rule in report_script.MUTATION_ARTIFACTS:
        assert (pid, mutation, rule) in r.mutations.artifacts
        others = sum(
            1
            for m in em.generate()
            if m.mutation == mutation
            and rule in m.expected
            and m.pattern_id in counted
            and m.pattern_id != pid
        )
        assert r.mutations.rates.get((rule, mutation), [0, 0])[1] == others


# --- collection helper policy (no container is started here)

GOOD = [
    *("docker", "run", "-i", "--rm", "--network", "none", "--read-only"),
    *("--cap-drop", "ALL", "--security-opt", "no-new-privileges"),
    *("--user", "65534:65534", "-v", "vol:/opt/srv:ro", "--entrypoint", "/usr/bin/env"),
    *("zqvex-image", "-i", "/usr/local/bin/node", "/opt/srv/x.js"),
]


def test_collect_policy_accepts_the_documented_command():
    assert collect.policy_violations(GOOD) == []


@pytest.mark.parametrize(
    "change",
    [
        lambda a: [x for x in a if x != "--read-only"],
        lambda a: [("bridge" if x == "none" else x) for x in a],
        lambda a: [("vol:/opt/srv" if x == "vol:/opt/srv:ro" else x) for x in a],
        lambda a: a[:2] + ["-e", "X=1"] + a[2:],
        lambda a: a[:2] + ["--env-file", "f"] + a[2:],
        lambda a: a[:2] + ["--privileged"] + a[2:],
        lambda a: [x for x in a if x not in ("--cap-drop", "ALL")],
        lambda a: ["podman", *a[1:]],
    ],
)
def test_collect_policy_rejects(change):
    assert collect.policy_violations(change(list(GOOD)))


def test_collect_docker_env_is_minimal(monkeypatch):
    monkeypatch.setenv("ZQVEX_SECRET_MARKER", "x")
    assert set(collect.docker_cli_env()) <= {
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
    }


# --- hygiene for the new files


def test_corpus_files_are_ascii():
    for path in corpus_files():
        assert path.read_bytes().isascii(), path.name


@pytest.mark.parametrize("path", NEW_FILES, ids=lambda p: p.name)
def test_new_files_hold_no_hidden_or_non_ascii_characters(path):
    text = path.read_text(encoding="utf-8")
    assert text.isascii(), path.name
    assert all(hidden_class(ch) is None for ch in text if ch not in "\n\t"), path.name


def test_corpus_and_new_files_hold_no_token_shaped_literals():
    for path in [*corpus_files(), *NEW_FILES]:
        assert find_secrets(path.read_text(encoding="utf-8")) == [], path.name


def test_manifest_and_benign_manifest_load():
    benign = yaml.safe_load((EVAL / "benign/MANIFEST.yaml").read_text(encoding="ascii"))
    assert benign["version"] == 1 and isinstance(benign["snapshots"], list)
    listed = {s["file"] for s in benign["snapshots"]}
    assert listed == {p.name for p in (EVAL / "benign").glob("*.json")}
    for s in benign["snapshots"]:
        assert (EVAL / "benign/LICENSES" / f"{Path(s['file']).stem}.txt").is_file()
