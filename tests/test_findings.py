import json
import re
from pathlib import Path

import pytest

from mcp_supply_audit.findings import (
    EVIDENCE_MAX_LEN,
    MERGE_SEPARATOR,
    NOTE,
    SKIP_REASON_TEXT,
    Assessment,
    AuditedPackage,
    Confidence,
    Coverage,
    DataSource,
    Finding,
    Severity,
    SkipDetail,
    SkippedCheck,
    SkipReason,
    build_report,
    merge_reports,
)
from mcp_supply_audit.owasp import OWASP_MCP_TOP_10


def make(rule_id="TD001", severity="medium", confidence="medium", **kw) -> Finding:
    defaults = {
        "title": "Example finding",
        "owasp": ["MCP03:2025"],
        "location": "tool:example/description@0",
        "evidence": "inert sample text",
        "remediation": "Remove the flagged text from the tool description.",
    }
    defaults.update(kw)
    return Finding(
        rule_id=rule_id, severity=severity, confidence=confidence, **defaults
    )


COVERAGE = Coverage(ran=("tool_definitions",))


def test_sorted_by_severity_then_confidence():
    findings = [
        make("TD001", "low", "high"),
        make("TD002", "critical", "low"),
        make("TD003", "high", "medium"),
        make("TD004", "critical", "high"),
        make("TD005", "info", "high"),
        make("TD006", "high", "high"),
    ]
    report = build_report(findings, COVERAGE)
    assert [f.rule_id for f in report.findings] == [
        "TD004",
        "TD002",
        "TD006",
        "TD003",
        "TD001",
        "TD005",
    ]


def test_sort_is_deterministic_for_equal_rank():
    a, b = make("TD002", location="x"), make("TD001", location="y")
    assert (
        build_report([a, b], COVERAGE).findings
        == build_report([b, a], COVERAGE).findings
    )


def test_counts_include_every_severity():
    findings = [make(severity="high"), make(severity="high"), make(severity="info")]
    report = build_report(findings, COVERAGE)
    assert report.summary == {
        Severity.CRITICAL: 0,
        Severity.HIGH: 2,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 1,
    }
    assert report.assessment is Assessment.FINDINGS_PRESENT
    assert report.to_dict()["summary"] == {
        "critical": 0,
        "high": 2,
        "medium": 0,
        "low": 0,
        "info": 1,
    }


def test_empty_report_still_carries_note():
    report = build_report([], COVERAGE)
    assert report.findings == ()
    assert report.assessment is Assessment.NO_FINDINGS_DETECTED
    assert report.note == NOTE
    assert "not proof of safety" in report.to_dict()["note"]
    assert set(report.summary.values()) == {0}


def test_note_cannot_be_overridden():
    with pytest.raises(TypeError):
        build_report([], COVERAGE).__class__(
            findings=(),
            summary={},
            coverage=COVERAGE,
            assessment=Assessment.NO_FINDINGS_DETECTED,
            note="all clear",
        )


def test_coverage_with_skipped_checks():
    coverage = Coverage(
        ran=("tool_definitions", "config"),
        skipped=(
            SkippedCheck("registry", "source_unreachable"),
            SkippedCheck("package", SkipReason.REMOTE_ONLY),
        ),
    )
    out = build_report([], coverage).to_dict()
    assert out["coverage"] == {
        "ran": ["tool_definitions", "config"],
        "skipped": [
            {
                "check": "registry",
                "reason": "source_unreachable",
                "text": SKIP_REASON_TEXT[SkipReason.SOURCE_UNREACHABLE],
            },
            {
                "check": "package",
                "reason": "remote_only",
                "text": SKIP_REASON_TEXT[SkipReason.REMOTE_ONLY],
            },
        ],
    }
    # Skipped checks never turn into a clean bill of health.
    assert out["assessment"] == "no_findings_detected"
    assert out["note"] == NOTE


def test_check_cannot_be_both_ran_and_skipped():
    with pytest.raises(ValueError, match="both ran and skipped"):
        Coverage(
            ran=("registry",),
            skipped=(SkippedCheck("registry", SkipReason.SOURCE_UNREACHABLE),),
        )


@pytest.mark.parametrize(
    "reason",
    [
        "",
        "timeout",
        "registry_unreachable",
        "rule_data_invalid",
        "not_a_json_object",
        "REMOTE_ONLY",
        " remote_only",
        None,
        3,
    ],
)
def test_skipped_check_rejects_reasons_outside_fixed_set(reason):
    with pytest.raises(ValueError):
        SkippedCheck("registry", reason)


def test_build_report_rejects_reason_outside_fixed_set():
    bad = SkippedCheck("registry", SkipReason.SOURCE_UNREACHABLE)
    object.__setattr__(bad, "reason", "registry_unreachable")  # bypass validation
    coverage = Coverage(skipped=(SkippedCheck("x", SkipReason.RULE_ERROR),))
    object.__setattr__(coverage, "skipped", (bad,))
    with pytest.raises(ValueError, match="fixed SkipReason set"):
        build_report([], coverage)


def test_fixed_reason_set_has_eight_members():
    assert [r.value for r in SkipReason] == [
        "unsupported_package_type",
        "remote_only",
        "response_too_large",
        "source_unreachable",
        "shape_mismatch",
        "not_applicable",
        "not_determinable",
        "rule_error",
    ]
    assert set(SKIP_REASON_TEXT) == set(SkipReason)


def test_reason_texts_match_finding_spec():
    spec = (Path(__file__).resolve().parents[1] / "docs/finding-spec.md").read_text(
        encoding="utf-8"
    )
    rows = dict(
        re.findall(r"^\| `([a-z_]+)` \|[^|]*\| ([^|]+?) \|$", spec, re.MULTILINE)
    )
    assert rows == {r.value: text for r, text in SKIP_REASON_TEXT.items()}


@pytest.mark.parametrize("field", ["severity", "confidence"])
@pytest.mark.parametrize("bad", ["severe", "HIGH", "", None, 3])
def test_invalid_enum_raises(field, bad):
    with pytest.raises(ValueError):
        make(**{field: bad})


def test_confidence_rejects_severity_only_values():
    with pytest.raises(ValueError):
        make(confidence="critical")


def test_string_enum_values_are_coerced():
    f = make(severity="critical", confidence="low")
    assert f.severity is Severity.CRITICAL
    assert f.confidence is Confidence.LOW


@pytest.mark.parametrize("owasp", [["MCP11:2025"], ["MCP01"], []])
def test_invalid_owasp_raises(owasp):
    with pytest.raises(ValueError):
        make(owasp=owasp)


def test_owasp_bare_string_raises():
    with pytest.raises(TypeError):
        make(owasp="MCP01:2025")


@pytest.mark.parametrize("rule_id", ["td001", "TD1", "TOOL001", ""])
def test_invalid_rule_id_raises(rule_id):
    with pytest.raises(ValueError):
        make(rule_id)


ZWSP, RLO, NUL = chr(0x200B), chr(0x202E), chr(0)
BS = chr(92)  # backslash


def test_evidence_is_escaped_capped_and_wrapped():
    raw = "a" + RLO + "b" + ZWSP + NUL + "c\n" + "x" * 500
    f = make(evidence=raw)
    assert f.evidence == raw  # stored raw; escaped only on output
    text = f.to_dict()["evidence"]["untrusted_text"]
    assert len(text) <= EVIDENCE_MAX_LEN
    assert text.startswith(f"a{BS}u202eb{BS}u200b{BS}u0000c x")
    assert text.endswith("[truncated]")


def test_evidence_snippet_starts_near_offset():
    raw = "y" * 1000 + ZWSP + "z" * 1000
    text = make(evidence=raw, evidence_start=1000).to_dict()["evidence"][
        "untrusted_text"
    ]
    assert f"{BS}u200b" in text
    assert len(text) <= EVIDENCE_MAX_LEN


def test_raw_evidence_never_leaks():
    marker = "EVIDENCE-MARKER-7f3a"
    raw = marker + ZWSP + RLO + BS + "u200b"
    f = make(evidence=raw)
    report = build_report([f], COVERAGE)
    out = json.dumps(report.to_dict(), ensure_ascii=False)
    assert raw not in out
    assert ZWSP not in out and RLO not in out
    assert (
        marker + f"{BS}u200b{BS}u202e{BS}{BS}u200b"
        in f.to_dict()["evidence"]["untrusted_text"]
    )
    # repr/str omit evidence entirely, escaped or not.
    for text in (repr(f), str(f), repr(report), str(report)):
        assert marker not in text


SERIALIZERS = re.compile(r"\b(asdict|astuple|vars)\s*\(|__dict__|__getstate__|pickle")


def test_no_alternate_finding_serialization_in_src():
    # Finding and Report are dataclasses; asdict() and friends would copy raw evidence.
    src = Path(__file__).resolve().parents[1] / "src"
    hits = [
        f"{p.name}:{n}"
        for p in src.rglob("*.py")
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if SERIALIZERS.search(line)
    ]
    assert not hits, hits


@pytest.mark.parametrize("start", [-1, 4, True, "0"])
def test_invalid_evidence_start_raises(start):
    with pytest.raises(ValueError):
        make(evidence="abc", evidence_start=start)


def test_owasp_table_shape():
    assert list(OWASP_MCP_TOP_10) == [f"MCP{n:02d}:2025" for n in range(1, 11)]


# --- skip details, notes, data sources


def test_skip_detail_is_optional_and_from_the_fixed_set():
    plain = SkippedCheck("TS003", SkipReason.NOT_APPLICABLE)
    detailed = SkippedCheck("TS003", "not_applicable", "name too short")
    assert plain.detail is None
    assert detailed.detail is SkipDetail.NAME_TOO_SHORT
    skipped = Coverage(skipped=(plain, detailed)).to_dict()["skipped"]
    assert "detail" not in skipped[0]
    assert skipped[1]["detail"] == "name too short"


@pytest.mark.parametrize("detail", ["free text from a target", "Name too short", 3])
def test_skip_detail_rejects_strings_outside_fixed_set(detail):
    with pytest.raises(ValueError):
        SkippedCheck("TS003", SkipReason.NOT_APPLICABLE, detail)


def test_skip_details_match_finding_spec():
    spec = (Path(__file__).resolve().parents[1] / "docs/finding-spec.md").read_text(
        encoding="utf-8"
    )
    section = spec.split("## Skip details (fixed set)")[1]
    rows = re.findall(r"^\| `([^`]+)` \|", section, re.MULTILINE)
    assert rows == [d.value for d in SkipDetail]


def test_notes_never_change_assessment():
    report = build_report([], COVERAGE, notes=["The reference data may be stale."])
    assert report.assessment is Assessment.NO_FINDINGS_DETECTED
    assert report.to_dict()["notes"] == ["The reference data may be stale."]
    assert report.note == NOTE


def test_optional_report_fields_absent_when_empty():
    rendered = build_report([], COVERAGE).to_dict()
    assert "notes" not in rendered and "data_sources" not in rendered


def test_data_sources_render_date_and_count():
    source = DataSource("data/reference_names.json", "2026-11-03", 10)
    rendered = build_report([], COVERAGE, data_sources=[source]).to_dict()
    assert rendered["data_sources"] == [
        {"name": "data/reference_names.json", "as_of": "2026-11-03", "entry_count": 10}
    ]


@pytest.mark.parametrize("count", [-1, True, "10"])
def test_data_source_rejects_bad_count(count):
    with pytest.raises(ValueError):
        DataSource("data/reference_names.json", "2026-11-03", count)


@pytest.mark.parametrize("note", ["", "   ", None])
def test_empty_notes_are_rejected(note):
    with pytest.raises(ValueError):
        build_report([], COVERAGE, notes=[note])


# --- merge_reports (audit_server)

REF = DataSource("data/reference_names.json", "2026-11-03", 10, partial=False)
PKG = AuditedPackage("pypi", "zqvex-pkg", "1.2.0")


def merge_parts():
    package = build_report(
        [make("PK001", "low", "high", location="advisories")],
        Coverage(ran=("PK001",), skipped=(SkippedCheck("PK003", "not_determinable"),)),
        audited=PKG,
    )
    typosquat = build_report(
        [make("TS001", "high", "medium", location="name")],
        Coverage(ran=("TS001",)),
        data_sources=[REF],
        notes=["Shared note.", NOTE],
    )
    registry_name = build_report(
        [], Coverage(ran=("TS001",)), data_sources=[REF], notes=["Shared note."]
    )
    return {
        "audit_package": package,
        "check_typosquat": typosquat,
        "check_typosquat:name": registry_name,
    }


def test_merge_combines_and_resorts_findings():
    merged = merge_reports(merge_parts())
    assert [f.rule_id for f in merged.findings] == ["TS001", "PK001"]
    assert [f.location for f in merged.findings] == [
        "check_typosquat/name",
        "audit_package/advisories",
    ]
    assert merged.summary[Severity.HIGH] == 1 and merged.summary[Severity.LOW] == 1
    assert merged.assessment is Assessment.FINDINGS_PRESENT


def test_merge_prefixes_coverage_and_adds_extra_skips():
    extra = SkippedCheck(
        "scan_tool_definitions",
        "source_unreachable",
        "check did not finish before the deadline",
    )
    merged = merge_reports(merge_parts(), skipped=[extra])
    assert merged.coverage.ran == (
        "audit_package/PK001",
        "check_typosquat/TS001",
        "check_typosquat:name/TS001",
    )
    assert merged.coverage.skipped == (
        SkippedCheck("audit_package/PK003", SkipReason.NOT_DETERMINABLE),
        extra,
    )
    assert MERGE_SEPARATOR == "/"


def test_merge_dedupes_sources_and_notes_and_keeps_audited_per_report():
    merged = merge_reports(merge_parts())
    assert merged.data_sources == (REF,)
    assert merged.notes == ("Shared note.",)  # the standing note is never a note
    assert merged.audited is None
    rendered = merged.to_dict()
    assert rendered["audited_by_report"] == {"audit_package": PKG.to_dict()}
    assert json.dumps(rendered).count(NOTE) == 1
    assert rendered["note"] == NOTE


def test_merge_recomputes_assessment_when_clean():
    clean = build_report([], Coverage(ran=("TD001",)))
    merged = merge_reports({"a": clean, "b": clean})
    assert merged.findings == ()
    assert merged.assessment is Assessment.NO_FINDINGS_DETECTED
    assert merged.coverage.ran == ("a/TD001", "b/TD001")
    assert merged.note == NOTE


def test_merge_of_merged_reports_nests_names():
    inner = merge_reports({"audit_package": merge_parts()["audit_package"]})
    outer = merge_reports({"outer": inner})
    assert outer.coverage.ran == ("outer/audit_package/PK001",)
    assert outer.to_dict()["audited_by_report"] == {
        "outer/audit_package": PKG.to_dict()
    }


def test_merge_rejects_bad_parts():
    with pytest.raises(TypeError):
        merge_reports({"a": "not a report"})
    with pytest.raises(ValueError):
        merge_reports({"": build_report([], COVERAGE)})
    # A skipped check that also ran is still refused after prefixing.
    clash = build_report([], Coverage(ran=("X",)))
    with pytest.raises(ValueError):
        merge_reports({"a": clash}, skipped=[SkippedCheck("a/X", "rule_error")])
