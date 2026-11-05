"""PK001-PK006 as pure functions over normalized metadata built from the synthetic fixtures in
tests/fixtures/package/ (shapes from docs/api-notes.md). No network. Invented zqvex-* names."""

import copy
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_supply_audit.clients import npm, pypi
from mcp_supply_audit.clients._http import Host, Response
from mcp_supply_audit.clients.osv import QueryResult, parse_page
from mcp_supply_audit.detectors import package_rules as rules
from mcp_supply_audit.detectors.package_rules import Skip
from mcp_supply_audit.findings import Severity, SkipDetail, SkipReason
from mcp_supply_audit.owasp import OWASP_MCP_TOP_10

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "tests/fixtures/package"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
ZWSP, RLO, BS = chr(0x200B), chr(0x202E), chr(92)


def load(name):
    return json.loads((PKG / name).read_text(encoding="ascii"))


RELEASE = load("pypi_release_zqvex.json")
NPM_DOC = load("npm_version_zqvex.json")
OSV = load("osv_query_zqvex.json")


def pypi_meta(mutate=None):
    data = copy.deepcopy(RELEASE)
    if mutate:
        mutate(data)
    return pypi.parse_release(data)


def npm_meta(mutate=None):
    data = copy.deepcopy(NPM_DOC)
    if mutate:
        mutate(data)
    return npm.parse_version_doc(data)


def osv_result(body, truncated=False):
    page = parse_page(Response(200, json.dumps(body).encode(), Host.OSV))
    return QueryResult(page.vulns, 1, truncated, "page_cap" if truncated else None)


def evidence(finding):
    return finding.to_dict()["evidence"]["untrusted_text"]


# --- benign baselines: the synthetic fixtures raise nothing except where noted


def test_baseline_pypi_release_has_no_findings():
    meta = pypi_meta()
    assert rules.pk002_yanked_or_deprecated("pypi", meta) == []
    assert rules.pk004_provenance("pypi", meta, (True, True)) == []
    assert rules.pk005_recent("pypi", meta, NOW) == []
    assert rules.pk006_repository("pypi", meta) == []


def test_baseline_npm_doc_has_no_findings():
    meta = npm_meta()
    for rule in (
        rules.pk002_yanked_or_deprecated,
        rules.pk003_install_scripts,
        rules.pk004_provenance,
        rules.pk006_repository,
    ):
        assert rule("npm", meta) == []


def test_empty_osv_answer_is_no_finding():
    assert rules.pk001_osv_advisories(osv_result({})) == []


# --- one positive per rule


def test_pk001_counts_advisories_and_takes_highest_label():
    [f] = rules.pk001_osv_advisories(osv_result(OSV))
    assert f.rule_id == "PK001"
    assert f.severity is Severity.HIGH
    assert f.title == "3 OSV advisories affect this version (highest label: HIGH)"
    assert evidence(f) == "GHSA-zqvx-0001-aaaa GHSA-zqvx-0002-bbbb PYSEC-2099-0003"
    assert "Invented advisory" not in json.dumps(f.to_dict())  # never summary/details


def test_pk001_without_labels_is_medium():
    pysec_only = {"vulns": [v for v in OSV["vulns"] if v["id"].startswith("PYSEC")]}
    [f] = rules.pk001_osv_advisories(osv_result(pysec_only))
    assert f.severity is Severity.MEDIUM
    assert f.title == "1 OSV advisory affects this version (highest label: none given)"


def test_pk001_unknown_label_counts_as_none():
    body = copy.deepcopy(OSV)
    for v in body["vulns"]:
        v.setdefault("database_specific", {})["severity"] = "SEVERE" + RLO
    [f] = rules.pk001_osv_advisories(osv_result(body))
    assert f.severity is Severity.MEDIUM
    assert RLO not in f.title and "SEVERE" not in f.title


def test_pk001_evidence_at_most_five_ids():
    vulns = [{"id": f"GHSA-zqvx-{i:04d}-cccc"} for i in range(8)]
    [f] = rules.pk001_osv_advisories(osv_result({"vulns": vulns}, truncated=True))
    assert f.title.startswith("At least 8 OSV advisories")
    assert evidence(f).split() == [v["id"] for v in vulns[:5]]


def test_pk001_truncated_with_nothing_collected_is_a_skip():
    assert rules.pk001_osv_advisories(osv_result({}, truncated=True)) == Skip(
        SkipReason.SHAPE_MISMATCH
    )


# --- PK001 advisory ids: every record counts, evidence shows only allowlisted ids

GOOD_ID = "GHSA-zqvx-0001-aaaa"
HIDDEN_ID = f"GHSA-zqvx{ZWSP}-0002{RLO}-bbbb\nPYSEC-2099-0002"
HUGE_ID = "GHSA-" + "z" * 10_240


def raw_result(records):
    """Records that parse_page would refuse (missing or non-string ids), passed straight in."""
    return QueryResult(tuple(records), 1, False, None)


@pytest.mark.parametrize(
    "value",
    [
        HIDDEN_ID,
        HUGE_ID,
        "GHSA-" + "z" * 60,  # 65 characters
        12345,
        None,
        ["GHSA-zqvx-0003-cccc"],
        "ZQVEX-2099-0001",  # unknown prefix
        "ghsa-zqvx-0004-dddd",  # prefixes are case-sensitive
        "GHSA-",
        "GHSA-zqvx 0005",
        "GHSA-zqvx/../0006",
        "GHSA-zqvx-0007\n",
        "GHSA-zqvx-é",
    ],
)
def test_advisory_id_refuses(value):
    assert rules.advisory_id(value) is None


@pytest.mark.parametrize(
    "value", [GOOD_ID, "PYSEC-2099-3", "GHSA-zqvx_0008.e-f", "GHSA-" + "z" * 59]
)
def test_advisory_id_accepts(value):
    assert rules.advisory_id(value) == value


def test_pk001_hidden_character_id_is_omitted_and_never_shown_raw():
    [f] = rules.pk001_osv_advisories(osv_result({"vulns": [{"id": HIDDEN_ID}]}))
    assert f.title == "1 OSV advisory affects this version (highest label: none given)"
    shown = evidence(f)
    assert shown == "1 id omitted"
    rendered = json.dumps(f.to_dict(), ensure_ascii=False)
    for hidden in (ZWSP, RLO, "\n"):
        assert hidden not in rendered
    assert "zqvx" not in rendered


def test_pk001_huge_id_is_omitted():
    [f] = rules.pk001_osv_advisories(
        osv_result({"vulns": [{"id": HUGE_ID}, {"id": GOOD_ID}]})
    )
    assert f.title.startswith("2 OSV advisories")
    assert evidence(f) == f"1 id omitted; {GOOD_ID}"


@pytest.mark.parametrize("bad", [{"id": 12345}, {"id": None}, {"id": ["x"]}, {}])
def test_pk001_missing_or_non_string_id_counts_and_does_not_raise(bad):
    [f] = rules.pk001_osv_advisories(raw_result([bad]))
    assert f.title.startswith("1 OSV advisory affects")
    assert evidence(f) == "1 id omitted"


def test_pk001_mixed_ids_count_every_record():
    records = [
        {"id": GOOD_ID, "database_specific": {"severity": "HIGH"}},
        {"id": HIDDEN_ID, "database_specific": {"severity": "CRITICAL"}},
        {"id": "ZQVEX-2099-0001"},
        {"id": 7},
        {},
        {"id": "PYSEC-2099-0003"},
    ]
    [f] = rules.pk001_osv_advisories(raw_result(records))
    # All six count, and the invalid record's label still sets the severity.
    assert f.title == "6 OSV advisories affect this version (highest label: CRITICAL)"
    assert f.severity is Severity.CRITICAL
    assert evidence(f) == f"4 ids omitted; {GOOD_ID} PYSEC-2099-0003"


def test_pk001_omitted_phrase_survives_the_evidence_cap():
    records = [{"id": "GHSA-" + "z" * 59}] * 5 + [{"id": "ZQVEX-1"}] * 3
    [f] = rules.pk001_osv_advisories(raw_result(records))
    assert evidence(f).startswith("3 ids omitted; GHSA-")
    assert len(evidence(f)) <= 120


def test_pk001_evidence_takes_first_five_passing_ids():
    records = [{"id": "ZQVEX-1"}] + [{"id": f"PYSEC-2099-{i}"} for i in range(7)]
    [f] = rules.pk001_osv_advisories(raw_result(records))
    assert evidence(f).split("; ")[1].split() == [f"PYSEC-2099-{i}" for i in range(5)]


def test_pk002_pypi_yanked_with_reason():
    def yank(d):
        d["info"]["yanked"] = True
        d["info"]["yanked_reason"] = "zqvex broken build"

    [f] = rules.pk002_yanked_or_deprecated("pypi", pypi_meta(yank))
    assert f.severity is Severity.MEDIUM
    assert evidence(f) == "yanked: zqvex broken build"


def test_pk002_pypi_yanked_without_reason():
    [f] = rules.pk002_yanked_or_deprecated(
        "pypi", pypi_meta(lambda d: d["info"].update(yanked=True))
    )
    assert evidence(f) == "yanked"


def test_pk002_npm_deprecated():
    [f] = rules.pk002_yanked_or_deprecated(
        "npm", npm_meta(lambda d: d.update(deprecated="use zqvex-pkg-next"))
    )
    assert f.title == "Version is deprecated on npm"
    assert evidence(f) == "deprecated: use zqvex-pkg-next"


def test_pk002_deprecation_message_hidden_characters_are_escaped():
    message = f"use zqvex-pkg-next{ZWSP} instead{RLO} now"
    [f] = rules.pk002_yanked_or_deprecated(
        "npm", npm_meta(lambda d: d.update(deprecated=message))
    )
    shown = evidence(f)
    assert f"{BS}u200b" in shown and f"{BS}u202e" in shown
    assert ZWSP not in json.dumps(f.to_dict(), ensure_ascii=False)
    assert RLO not in json.dumps(f.to_dict(), ensure_ascii=False)
    assert ZWSP not in f.title and ZWSP not in f.location


def test_pk002_long_deprecation_message_is_capped():
    [f] = rules.pk002_yanked_or_deprecated(
        "npm", npm_meta(lambda d: d.update(deprecated="zqvex " * 200))
    )
    assert len(evidence(f)) <= 120


def test_pk002_empty_deprecation_is_not_deprecated():
    assert (
        rules.pk002_yanked_or_deprecated(
            "npm", npm_meta(lambda d: d.update(deprecated=""))
        )
        == []
    )


def test_pk003_npm_install_scripts_names_only():
    scripts = {
        "postinstall": "node zqvex-install-marker.js",
        "test": "node --test",
        "preinstall": "node zqvex-preinstall-marker.js",
    }
    [f] = rules.pk003_install_scripts(
        "npm", npm_meta(lambda d: d.update(scripts=scripts))
    )
    assert f.severity is Severity.MEDIUM
    assert evidence(f) == "preinstall, postinstall"
    assert "marker" not in json.dumps(f.to_dict())


def test_pk003_client_never_keeps_command_text():
    meta = npm_meta(
        lambda d: d.update(scripts={"install": "node zqvex-install-marker.js"})
    )
    assert meta["install_scripts"] == ("install",)
    assert "marker" not in repr(meta)


def test_pk003_pypi_is_a_fixed_skip():
    assert rules.pk003_install_scripts("pypi", pypi_meta()) == Skip(
        SkipReason.NOT_DETERMINABLE, SkipDetail.PYPI_INSTALL_CODE
    )


def test_pk004_npm_without_attestations():
    [f] = rules.pk004_provenance(
        "npm", npm_meta(lambda d: d["dist"].pop("attestations"))
    )
    assert (f.severity, f.confidence.value) == (Severity.INFO, "medium")


def test_pk004_pypi_every_file_without_provenance():
    [f] = rules.pk004_provenance("pypi", pypi_meta(), (False, False))
    assert f.title == "No provenance attestation for this version"


def test_pk004_pypi_any_file_with_provenance_passes():
    assert rules.pk004_provenance("pypi", pypi_meta(), (False, True)) == []
    # A failed request does not matter once another file has provenance.
    assert (
        rules.pk004_provenance(
            "pypi", pypi_meta(), (SkipReason.SOURCE_UNREACHABLE, True)
        )
        == []
    )


def test_pk004_pypi_more_files_than_checked_is_a_skip():
    def six_files(d):
        d["urls"] = [
            dict(d["urls"][0], filename=f"zqvex_pkg-{i}.whl") for i in range(6)
        ]

    answers = (False,) * rules.MAX_PROVENANCE_FILES
    assert rules.pk004_provenance("pypi", pypi_meta(six_files), answers) == Skip(
        SkipReason.NOT_DETERMINABLE, SkipDetail.TOO_MANY_FILES
    )


def with_files(n):
    def mutate(d):
        d["urls"] = [
            dict(d["urls"][0], filename=f"zqvex_pkg-1.2.0-{i}.whl") for i in range(n)
        ]

    return mutate


@pytest.mark.parametrize("n", [1, 2, 4])
def test_pk004_pypi_location_counts_files_checked(n):
    [f] = rules.pk004_provenance("pypi", pypi_meta(with_files(n)), (False,) * n)
    assert f.location == f"PyPI /integrity provenance, {n} of {n} files checked@0"


def test_pk004_npm_location_unchanged():
    [f] = rules.pk004_provenance(
        "npm", npm_meta(lambda d: d["dist"].pop("attestations"))
    )
    assert f.location == "npm dist.attestations@0"


@pytest.mark.parametrize("n", [5, 6, 66])
def test_pk004_pypi_more_than_four_files_is_never_a_finding(n):
    answers = (False,) * rules.MAX_PROVENANCE_FILES
    assert rules.pk004_provenance("pypi", pypi_meta(with_files(n)), answers) == Skip(
        SkipReason.NOT_DETERMINABLE, SkipDetail.TOO_MANY_FILES
    )


def test_rules_doc_states_the_provenance_file_cap():
    text = (ROOT / "docs/rules-package.md").read_text(encoding="utf-8")
    cap = str(rules.MAX_PROVENANCE_FILES)
    assert re.findall(
        r"PyPI provenance is checked only for versions with at most (\d+) files "
        r"\(MAX_PROVENANCE_FILES\); larger versions get a skip\.",
        text,
    ) == [cap]
    # Every other place the doc states the cap.
    stated = re.findall(
        r"at most (\d+) (?:files per version|are checked)|first (\d+) files"
        r"|more than (\d+) files|none of the (\d+) checked",
        text,
    )
    assert len(stated) >= 4
    assert {n for groups in stated for n in groups if n} == {cap}


def test_pk004_pypi_failed_request_is_a_skip():
    assert rules.pk004_provenance(
        "pypi", pypi_meta(), (False, SkipReason.SOURCE_UNREACHABLE)
    ) == Skip(SkipReason.SOURCE_UNREACHABLE)


def test_pk005_pypi_recent_upload():
    def recent(d):
        for f in d["urls"]:
            f["upload_time_iso_8601"] = "2026-11-02T08:00:00.000000Z"

    [f] = rules.pk005_recent("pypi", pypi_meta(recent), NOW)
    assert (f.severity, f.confidence.value) == (Severity.INFO, "low")
    assert evidence(f) == "2026-11-02T08:00:00.000000Z"


def test_pk005_uses_the_earliest_file():
    # One old file means the version is not new, even if a later file was just added.
    def one_new(d):
        d["urls"][1]["upload_time_iso_8601"] = "2026-11-03T08:00:00.000000Z"

    assert rules.pk005_recent("pypi", pypi_meta(one_new), NOW) == []

    def both_new(d):
        for i, f in enumerate(d["urls"]):
            f["upload_time_iso_8601"] = f"2026-11-0{3 - i}T08:00:00.000000Z"

    [f] = rules.pk005_recent("pypi", pypi_meta(both_new), NOW)
    assert evidence(f) == "2026-11-02T08:00:00.000000Z"


def test_pk005_npm_is_a_fixed_skip():
    assert rules.pk005_recent("npm", npm_meta(), NOW) == Skip(
        SkipReason.NOT_DETERMINABLE, SkipDetail.NPM_NO_PUBLISH_TIME
    )


def test_pk006_pypi_no_project_urls():
    [f] = rules.pk006_repository(
        "pypi", pypi_meta(lambda d: d["info"].update(project_urls=None))
    )
    assert (f.severity, f.confidence.value) == (Severity.LOW, "medium")


def test_pk006_pypi_home_page_counts():
    def home_only(d):
        d["info"].update(project_urls=None, home_page="https://zqvex.example/")

    assert rules.pk006_repository("pypi", pypi_meta(home_only)) == []


def test_pk006_npm_no_repository():
    [f] = rules.pk006_repository("npm", npm_meta(lambda d: d.pop("repository")))
    assert f.location.startswith("npm repository")


def test_pk006_npm_shorthand_repository_counts():
    meta = npm_meta(lambda d: d.update(repository="github:zqvex/zqvex-pkg"))
    assert rules.pk006_repository("npm", meta) == []


# --- zero files and malformed fields skip only the rules that need them


def test_zero_file_pypi_version():
    meta = pypi_meta(lambda d: d.update(urls=[]))
    assert rules.pk004_provenance("pypi", meta) == Skip(
        SkipReason.NOT_APPLICABLE, SkipDetail.NO_FILES
    )
    assert rules.pk005_recent("pypi", meta, NOW) == Skip(
        SkipReason.NOT_DETERMINABLE, SkipDetail.NO_FILES
    )


@pytest.mark.parametrize(
    ("mutate", "rule"),
    [
        (
            lambda d: d["info"].update(yanked="yes"),
            lambda m: rules.pk002_yanked_or_deprecated("pypi", m),
        ),
        (
            lambda d: d["urls"].append("zqvex"),
            lambda m: rules.pk004_provenance("pypi", m),
        ),
        (
            lambda d: d["urls"][0].update(upload_time_iso_8601="2026-09-01T10:00:00"),
            lambda m: rules.pk005_recent("pypi", m, NOW),
        ),
    ],
)
def test_malformed_pypi_field_is_shape_mismatch(mutate, rule):
    assert rule(pypi_meta(mutate)) == Skip(SkipReason.SHAPE_MISMATCH)


@pytest.mark.parametrize(
    ("mutate", "rule"),
    [
        (lambda d: d.update(deprecated=True), rules.pk002_yanked_or_deprecated),
        (lambda d: d.update(scripts="node x"), rules.pk003_install_scripts),
        (lambda d: d.update(dist="zqvex"), rules.pk004_provenance),
    ],
)
def test_malformed_npm_field_is_shape_mismatch(mutate, rule):
    assert rule("npm", npm_meta(mutate)) == Skip(SkipReason.SHAPE_MISMATCH)


# --- titles and locations never carry target text


def test_titles_and_locations_are_fixed_text():
    hostile = f"zqvex{RLO}{ZWSP}<script>"

    def everything(d):
        d["info"].update(yanked=True, yanked_reason=hostile, project_urls=None)

    findings = rules.pk002_yanked_or_deprecated("pypi", pypi_meta(everything))
    findings += rules.pk006_repository("pypi", pypi_meta(everything))
    for f in findings:
        assert "zqvex" not in f.title and "zqvex" not in f.location


# --- OWASP table


def owasp_table() -> dict[str, tuple[str, ...]]:
    text = (ROOT / "docs/rules-package.md").read_text(encoding="utf-8")
    section = text.split("## OWASP MCP Top 10 mapping", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(
        r"^\| (PK\d{3}) \| (MCP\d\d:\d{4}(?:, MCP\d\d:\d{4})*) \| (.+) \|$",
        section,
        re.MULTILINE,
    )
    assert all(r[2].strip() for r in rows), "every row needs a rationale"
    return {rule: tuple(ids.split(", ")) for rule, ids, _ in rows}


def test_owasp_table_matches_code_and_owasp_ids():
    table = owasp_table()
    assert table == dict(rules.RULE_OWASP)
    assert tuple(table) == rules.RULE_IDS
    for ids in table.values():
        for owasp_id in ids:
            assert owasp_id in OWASP_MCP_TOP_10
