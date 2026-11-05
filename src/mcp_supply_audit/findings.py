"""Finding and Report types. Rules live in docs/finding-spec.md; read it before changing this."""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Final

from mcp_supply_audit.owasp import OWASP_MCP_TOP_10
from mcp_supply_audit.sanitize import evidence_snippet

EVIDENCE_MAX_LEN: Final = 120

NOTE: Final = (
    "Absence of findings is not proof of safety. Only static checks were run; "
    "see coverage for which checks ran and which were skipped."
)

_RULE_ID_RE = re.compile(r"^[A-Z]{2}\d{3}$")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Assessment(StrEnum):
    FINDINGS_PRESENT = "findings_present"
    NO_FINDINGS_DETECTED = "no_findings_detected"


class SkipReason(StrEnum):
    """The fixed set of reasons a check can be skipped (docs/finding-spec.md)."""

    UNSUPPORTED_PACKAGE_TYPE = "unsupported_package_type"
    REMOTE_ONLY = "remote_only"
    RESPONSE_TOO_LARGE = "response_too_large"
    SOURCE_UNREACHABLE = "source_unreachable"
    SHAPE_MISMATCH = "shape_mismatch"
    NOT_APPLICABLE = "not_applicable"
    NOT_DETERMINABLE = "not_determinable"
    RULE_ERROR = "rule_error"


# Shown with each skipped check so the report states its limits in plain words.
# Must match the table in docs/finding-spec.md (tests compare them).
SKIP_REASON_TEXT: Final[dict[SkipReason, str]] = {
    SkipReason.UNSUPPORTED_PACKAGE_TYPE: (
        "Package type not supported: its registry is outside the allowed hosts, "
        "so this check did not run."
    ),
    SkipReason.REMOTE_ONLY: (
        "Remote-only server: package checks do not apply. "
        "The remote URL was checked as text and never contacted."
    ),
    SkipReason.RESPONSE_TOO_LARGE: (
        "A source response exceeded the size cap, so this check did not run."
    ),
    SkipReason.SOURCE_UNREACHABLE: (
        "A data source could not be reached, so this check did not run."
    ),
    SkipReason.SHAPE_MISMATCH: (
        "Data was not in the expected shape, so this check did not run."
    ),
    SkipReason.NOT_APPLICABLE: (
        "This check does not apply to this kind of target, so it did not run."
    ),
    SkipReason.NOT_DETERMINABLE: (
        "The data this check needs cannot be determined from the allowed sources, "
        "so it did not run."
    ),
    SkipReason.RULE_ERROR: (
        "This check failed with an internal error, so its result is unknown."
    ),
}


class SkipDetail(StrEnum):
    """Optional detail on a skipped check: fixed strings only, never target text
    (docs/finding-spec.md)."""

    NAME_TOO_SHORT = "name too short"
    NO_SCOPE = "name has no scope or namespace"
    REFERENCE_ENTRY = "name is a reference entry"
    NO_REFERENCE_NAMES = "no reference names for this ecosystem"
    REFERENCE_FILE_MALFORMED = "reference file malformed"
    REFERENCE_FILE_UNREADABLE = "reference file unreadable"
    NOT_USED_FOR_REGISTRY = "rule not used for registry names"
    PYPI_INSTALL_CODE = "PyPI install-time code needs file download"
    NO_FILES = "version has no files"
    TOO_MANY_FILES = "too many files to check"
    NPM_NO_PUBLISH_TIME = "npm version document has no publish time"
    TOO_MANY_SERVERS = "too many servers"
    SERVER_OVER_LIMIT = "server over a size limit"
    SERVER_MALFORMED = "server entry malformed"
    RUNNER_SYNTAX = "runner syntax not documented"
    PLACEHOLDER = "value is a placeholder"
    LATEST_UNRESOLVED = "latest version could not be resolved"
    PACKAGE_NOT_FOUND = "package or version not found"
    REGISTRY_NOT_PROVIDED = "registry entry not provided"
    REGISTRY_NOT_FOUND = "registry entry not found"
    PACKAGE_LIMIT = "more packages than audit_server checks"
    DEADLINE = "check did not finish before the deadline"


# Enum declaration order is most-severe first; sort keys index into it.
_SEVERITY_RANK: Final = {s: i for i, s in enumerate(Severity)}
_CONFIDENCE_RANK: Final = {c: i for i, c in enumerate(Confidence)}


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    owasp: tuple[str, ...]
    location: str
    # Raw hostile text from the target. Kept out of repr; only to_dict() renders it,
    # through evidence_snippet, so hidden characters are escaped rather than dropped.
    evidence: str = field(repr=False)
    remediation: str
    # Offset into evidence of the flagged text; the snippet is excerpted around it.
    evidence_start: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not _RULE_ID_RE.match(self.rule_id):
            raise ValueError(f"invalid rule_id {self.rule_id!r}; expected e.g. TD001")
        _require_text("title", self.title)
        _require_text("location", self.location)
        _require_text("remediation", self.remediation)
        # Severity("bogus") raises ValueError; plain strings matching a value are accepted.
        object.__setattr__(self, "severity", Severity(self.severity))
        object.__setattr__(self, "confidence", Confidence(self.confidence))

        if isinstance(self.owasp, str):
            raise TypeError("owasp must be a list of ids, not a single string")
        owasp = tuple(self.owasp)
        if not owasp:
            raise ValueError("owasp must name at least one OWASP MCP Top 10 id")
        unknown = [i for i in owasp if i not in OWASP_MCP_TOP_10]
        if unknown:
            raise ValueError(f"unknown OWASP MCP Top 10 id(s): {unknown}")
        object.__setattr__(self, "owasp", owasp)

        if not isinstance(self.evidence, str):
            raise TypeError("evidence must be a str")
        if (
            isinstance(self.evidence_start, bool)
            or not isinstance(self.evidence_start, int)
            or not 0 <= self.evidence_start <= len(self.evidence)
        ):
            raise ValueError("evidence_start must be an offset within evidence")

    def sort_key(self) -> tuple[int, int, str, str]:
        # rule_id and location only make the order deterministic among equal ranks.
        return (
            _SEVERITY_RANK[self.severity],
            _CONFIDENCE_RANK[self.confidence],
            self.rule_id,
            self.location,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "owasp": list(self.owasp),
            "location": self.location,
            "evidence": {
                "untrusted_text": evidence_snippet(
                    self.evidence, self.evidence_start, EVIDENCE_MAX_LEN
                )
            },
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class SkippedCheck:
    check: str
    reason: SkipReason
    detail: SkipDetail | None = None

    def __post_init__(self) -> None:
        _require_text("check", self.check)
        # SkipReason("anything else") raises ValueError; matching strings are accepted.
        object.__setattr__(self, "reason", SkipReason(self.reason))
        if self.detail is not None:
            object.__setattr__(self, "detail", SkipDetail(self.detail))


@dataclass(frozen=True)
class Coverage:
    ran: tuple[str, ...] = ()
    skipped: tuple[SkippedCheck, ...] = ()

    def __post_init__(self) -> None:
        ran = tuple(_require_text("ran check", c) for c in self.ran)
        skipped = tuple(self.skipped)
        if not all(isinstance(s, SkippedCheck) for s in skipped):
            raise ValueError("skipped entries must be SkippedCheck")
        both = set(ran) & {s.check for s in skipped}
        if both:
            raise ValueError(f"check(s) both ran and skipped: {sorted(both)}")
        object.__setattr__(self, "ran", ran)
        object.__setattr__(self, "skipped", skipped)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran": list(self.ran),
            "skipped": [
                {
                    "check": s.check,
                    "reason": s.reason.value,
                    "text": SKIP_REASON_TEXT[s.reason],
                    **({"detail": s.detail.value} if s.detail is not None else {}),
                }
                for s in self.skipped
            ],
        }


@dataclass(frozen=True)
class DataSource:
    """A dated data file a check compared against, e.g. the typosquat reference names."""

    name: str
    as_of: str
    entry_count: int
    # Whether the file holds only part of its source (e.g. a crawl stopped at its page cap).
    # None when the data source does not record it; omitted from to_dict() then.
    partial: bool | None = None

    def __post_init__(self) -> None:
        _require_text("name", self.name)
        _require_text("as_of", self.as_of)
        if (
            isinstance(self.entry_count, bool)
            or not isinstance(self.entry_count, int)
            or self.entry_count < 0
        ):
            raise ValueError("entry_count must be a non-negative int")
        if self.partial is not None and not isinstance(self.partial, bool):
            raise ValueError("partial must be a bool or None")

    def to_dict(self) -> dict[str, Any]:
        rendered: dict[str, Any] = {
            "name": self.name,
            "as_of": self.as_of,
            "entry_count": self.entry_count,
        }
        if self.partial is not None:
            rendered["partial"] = self.partial
        return rendered


@dataclass(frozen=True)
class AuditedPackage:
    """The package a package audit checked. All three strings passed validation.py."""

    ecosystem: str
    name: str
    version: str

    def __post_init__(self) -> None:
        _require_text("ecosystem", self.ecosystem)
        _require_text("name", self.name)
        _require_text("version", self.version)

    def to_dict(self) -> dict[str, str]:
        return {"ecosystem": self.ecosystem, "name": self.name, "version": self.version}


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    summary: dict[Severity, int]
    coverage: Coverage
    assessment: Assessment
    data_sources: tuple[DataSource, ...] = ()
    # Info notes: fixed wording plus a date or count only. They never change assessment.
    notes: tuple[str, ...] = ()
    audited: AuditedPackage | None = None
    # A merged report's audited packages, keyed by sub-report name (merge_reports).
    audited_by_report: tuple[tuple[str, AuditedPackage], ...] = ()
    # Not an init parameter, so no caller can drop or reword it.
    note: str = field(default=NOTE, init=False)

    def to_dict(self) -> dict[str, Any]:
        optional: dict[str, Any] = {}
        if self.data_sources:
            optional["data_sources"] = [d.to_dict() for d in self.data_sources]
        if self.notes:
            optional["notes"] = list(self.notes)
        if self.audited is not None:
            optional["audited"] = self.audited.to_dict()
        if self.audited_by_report:
            optional["audited_by_report"] = {
                name: a.to_dict() for name, a in self.audited_by_report
            }
        return {
            "findings": [f.to_dict() for f in self.findings],
            "summary": {s.value: n for s, n in self.summary.items()},
            "coverage": self.coverage.to_dict(),
            "assessment": self.assessment.value,
            **optional,
            "note": self.note,
        }


def build_report(
    findings: Iterable[Finding],
    coverage: Coverage,
    *,
    data_sources: Iterable[DataSource] = (),
    notes: Iterable[str] = (),
    audited: AuditedPackage | None = None,
    audited_by_report: Iterable[tuple[str, AuditedPackage]] = (),
) -> Report:
    """Sort findings (severity, then confidence), count by severity, and set the assessment.

    The summary always has every severity, zeros included. An empty report says
    "no_findings_detected", never "safe", and still carries the note. Every skipped
    check must carry a reason from the fixed SkipReason set. Notes and data sources are
    recorded as given and never affect the assessment, as are the audited packages.
    """
    data_sources = tuple(data_sources)
    if not all(isinstance(d, DataSource) for d in data_sources):
        raise ValueError("data_sources entries must be DataSource")
    notes = tuple(_require_text("note", n) for n in notes)
    if audited is not None and not isinstance(audited, AuditedPackage):
        raise ValueError("audited must be an AuditedPackage")
    audited_by_report = tuple(audited_by_report)
    for name, package in audited_by_report:
        _require_text("audited report name", name)
        if not isinstance(package, AuditedPackage):
            raise TypeError("audited_by_report values must be AuditedPackage")
    for s in coverage.skipped:
        # SkippedCheck already coerces; this also catches one built around validation.
        try:
            SkipReason(s.reason)
        except ValueError:
            raise ValueError(
                "skipped check reason is not in the fixed SkipReason set"
            ) from None
    ordered = tuple(sorted(findings, key=Finding.sort_key))
    summary = {s: 0 for s in Severity}
    for f in ordered:
        summary[f.severity] += 1
    assessment = (
        Assessment.FINDINGS_PRESENT if ordered else Assessment.NO_FINDINGS_DETECTED
    )
    return Report(
        findings=ordered,
        summary=summary,
        coverage=coverage,
        assessment=assessment,
        data_sources=data_sources,
        notes=notes,
        audited=audited,
        audited_by_report=audited_by_report,
    )


# Joins a sub-report name to a check or location in a merged report.
MERGE_SEPARATOR: Final = "/"


def merge_reports(
    reports: Mapping[str, Report], *, skipped: Iterable[SkippedCheck] = ()
) -> Report:
    """Combine named sub-reports into one Report (audit_server).

    Findings are combined and re-sorted, each location prefixed with its sub-report name.
    Coverage entries are prefixed the same way; `skipped` adds checks that produced no
    sub-report and is recorded as given. Data sources and notes are concatenated without
    duplicates. Audited packages are kept per sub-report. The assessment is recomputed,
    and the standing note appears once, as on every Report.
    """
    findings: list[Finding] = []
    ran: list[str] = []
    skips: list[SkippedCheck] = []
    data_sources: dict[DataSource, None] = {}
    notes: dict[str, None] = {}
    audited: list[tuple[str, AuditedPackage]] = []
    for name, report in reports.items():
        _require_text("report name", name)
        if not isinstance(report, Report):
            raise TypeError("reports values must be Report")
        prefix = f"{name}{MERGE_SEPARATOR}"
        findings.extend(
            replace(f, location=prefix + f.location) for f in report.findings
        )
        ran.extend(prefix + c for c in report.coverage.ran)
        skips.extend(
            SkippedCheck(prefix + s.check, s.reason, s.detail)
            for s in report.coverage.skipped
        )
        data_sources.update(dict.fromkeys(report.data_sources))
        notes.update(dict.fromkeys(n for n in report.notes if n != NOTE))
        if report.audited is not None:
            audited.append((name, report.audited))
        audited.extend((prefix + sub, a) for sub, a in report.audited_by_report)
    skips.extend(skipped)
    return build_report(
        findings,
        Coverage(ran=tuple(ran), skipped=tuple(skips)),
        data_sources=data_sources,
        notes=notes,
        audited_by_report=audited,
    )
