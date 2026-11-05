"""PK001-PK006: pure functions over a package version's normalized metadata, its OSV result,
and (PyPI) per-file provenance answers. Rules live in docs/rules-package.md; read it before
changing this. Inputs come from clients/pypi.py, clients/npm.py and clients/osv.py.

Each rule returns a list of Findings, or a Skip carrying a reason from the fixed set and an
optional fixed detail. Titles and locations are written here and never contain target text;
target text is only evidence, which Finding.to_dict() renders through evidence_snippet.
"""

import functools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from mcp_supply_audit.clients.osv import QueryResult
from mcp_supply_audit.detectors.tool_defs import RuleDataError, load_rule_data
from mcp_supply_audit.findings import (
    Confidence,
    Finding,
    Severity,
    SkipDetail,
    SkipReason,
)
from mcp_supply_audit.secrets import scrub

PackageMeta = Mapping[str, Any]


@dataclass(frozen=True)
class Skip:
    reason: SkipReason
    detail: SkipDetail | None = None


RuleResult = list[Finding] | Skip

RULE_IDS: Final = ("PK001", "PK002", "PK003", "PK004", "PK005", "PK006")

_O_SUPPLY: Final = ("MCP04:2025",)

# OWASP MCP Top 10 per rule; docs/rules-package.md has the same table with a rationale
# per row (tests compare them, and check the ids against owasp.py).
RULE_OWASP: Final[Mapping[str, tuple[str, ...]]] = {r: _O_SUPPLY for r in RULE_IDS}

# OSV database_specific.severity labels seen (api-notes, "OSV severity labels").
_LABEL_SEVERITY: Final[Mapping[str, Severity]] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_MAX_ADVISORY_IDS: Final = 5
# Advisory ids shown in PK001 evidence: a prefix from this file, then the tail pattern only.
_ADVISORY_ID_PREFIXES_FILE: Final = "pk001_advisory_id_prefixes.yaml"
_ADVISORY_ID_MAX_LEN: Final = 64
_ADVISORY_ID_TAIL: Final = re.compile(r"[A-Za-z0-9._-]+")
# PyPI provenance is one request per file; at most this many are checked per version.
MAX_PROVENANCE_FILES: Final = 4
RECENT_DAYS: Final = 7


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    location: str,
    evidence: str,
    remediation: str,
    start: int = 0,
) -> Finding:
    # Secret-shaped text never reaches a Finding, whatever the rule (secrets.py).
    evidence, start = scrub(evidence, start)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        owasp=RULE_OWASP[rule_id],
        location=f"{location}@{start}",
        evidence=evidence,
        remediation=remediation,
        evidence_start=start,
    )


def _label(vuln: Mapping[str, Any]) -> str | None:
    """The record's severity label if it is one of the known four, else None."""
    specific = vuln.get("database_specific")
    label = specific.get("severity") if isinstance(specific, Mapping) else None
    return label if label in _LABEL_SEVERITY else None


@functools.cache
def _advisory_id_prefixes() -> tuple[str, ...]:
    prefixes = load_rule_data(_ADVISORY_ID_PREFIXES_FILE).get("prefixes")
    if (
        not isinstance(prefixes, list)
        or not prefixes
        or not all(isinstance(p, str) and p.isascii() and p.strip() for p in prefixes)
    ):
        raise RuleDataError(
            f"{_ADVISORY_ID_PREFIXES_FILE}: prefixes must be a non-empty list of strings"
        )
    return tuple(prefixes)


def advisory_id(value: object) -> str | None:
    """The OSV id if it may be shown: an ASCII str of at most 64 characters, a known prefix
    (data/pk001_advisory_id_prefixes.yaml), then [A-Za-z0-9._-] only. Else None."""
    if (
        not isinstance(value, str)
        or len(value) > _ADVISORY_ID_MAX_LEN
        or not value.isascii()
    ):
        return None
    for prefix in _advisory_id_prefixes():
        if value.startswith(prefix) and _ADVISORY_ID_TAIL.fullmatch(
            value[len(prefix) :]
        ):
            return value
    return None


def pk001_osv_advisories(result: QueryResult) -> RuleResult:
    """PK001: OSV lists advisories for this exact version. Severity from the highest label.
    Every record counts; evidence shows only ids that pass advisory_id."""
    vulns = result.vulns
    if not vulns:
        # A token with no records cannot be counted; "at least 0" would read as a pass.
        return Skip(SkipReason.SHAPE_MISMATCH) if result.truncated else []
    labels = {label for v in vulns if (label := _label(v)) is not None}
    ranked = sorted(labels, key=lambda lbl: list(Severity).index(_LABEL_SEVERITY[lbl]))
    highest = ranked[0] if ranked else None
    count = len(vulns)
    noun = "advisory affects" if count == 1 else "advisories affect"
    prefix = "At least " if result.truncated else ""
    shown = highest if highest is not None else "none given"
    # parse_page already refuses a record without a str id; checked here regardless.
    ids = [
        i
        for v in vulns
        if (i := advisory_id(v.get("id") if isinstance(v, Mapping) else None))
        is not None
    ]
    parts = []
    if omitted := count - len(ids):
        # First, so the 120-character evidence cap never hides it.
        parts.append(f"{omitted} {'id' if omitted == 1 else 'ids'} omitted;")
    parts.extend(ids[:_MAX_ADVISORY_IDS])
    return [
        _finding(
            "PK001",
            f"{prefix}{count} OSV {noun} this version (highest label: {shown})",
            _LABEL_SEVERITY[highest] if highest is not None else Severity.MEDIUM,
            Confidence.HIGH,
            "OSV /v1/query",
            " ".join(parts).removesuffix(";"),
            "Upgrade to a version the advisories list as fixed, or confirm they do not apply.",
        )
    ]


def pk002_yanked_or_deprecated(ecosystem: str, meta: PackageMeta) -> RuleResult:
    """PK002: PyPI version yanked, or npm version deprecated."""
    if ecosystem == "pypi":
        yanked = meta["yanked"]
        if yanked is None:
            return Skip(SkipReason.SHAPE_MISMATCH)
        if not yanked:
            return []
        reason = meta["yanked_reason"]
        return [
            _finding(
                "PK002",
                "Version is yanked on PyPI",
                Severity.MEDIUM,
                Confidence.HIGH,
                "PyPI info.yanked_reason",
                f"yanked: {reason}" if reason else "yanked",
                "Pick a version that is not yanked; the reason, if given, says why.",
            )
        ]
    message = meta["deprecated"]
    if meta["deprecated_present"] and message is None:
        return Skip(SkipReason.SHAPE_MISMATCH)
    if not message:  # absent, or an empty string (treated as not deprecated)
        return []
    return [
        _finding(
            "PK002",
            "Version is deprecated on npm",
            Severity.MEDIUM,
            Confidence.HIGH,
            "npm deprecated",
            f"deprecated: {message}",
            "Prefer a version that is not deprecated, or the replacement the message names.",
        )
    ]


def pk003_install_scripts(ecosystem: str, meta: PackageMeta) -> RuleResult:
    """PK003: npm preinstall/install/postinstall present. Names only, never commands."""
    if ecosystem == "pypi":
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.PYPI_INSTALL_CODE)
    hooks: tuple[str, ...] | None = meta["install_scripts"]
    if hooks is None:
        return Skip(SkipReason.SHAPE_MISMATCH)
    if not hooks:
        return []
    return [
        _finding(
            "PK003",
            "Package runs scripts at install time",
            Severity.MEDIUM,
            Confidence.HIGH,
            "npm scripts",
            ", ".join(hooks),
            "Read the scripts before installing, or install with scripts disabled.",
        )
    ]


_PK004_TITLE: Final = "No provenance attestation for this version"
_PK004_REMEDIATION: Final = (
    "Prefer a version published with provenance, or verify the artifact another way."
)


def pk004_provenance(
    ecosystem: str,
    meta: PackageMeta,
    pypi_answers: Sequence[bool | SkipReason] = (),
) -> RuleResult:
    """PK004: no provenance. npm reads dist.attestations; PyPI takes one answer per checked
    file (True, False, or the skip reason of a failed request), in file order."""
    if ecosystem == "npm":
        has = meta["has_provenance"]
        if has is None:
            return Skip(SkipReason.SHAPE_MISMATCH)
        if has:
            return []
        return [
            _finding(
                "PK004",
                _PK004_TITLE,
                Severity.INFO,
                Confidence.MEDIUM,
                "npm dist.attestations",
                "",
                _PK004_REMEDIATION,
            )
        ]
    files = meta["files"]
    if files is None:
        return Skip(SkipReason.SHAPE_MISMATCH)
    if not files:
        return Skip(SkipReason.NOT_APPLICABLE, SkipDetail.NO_FILES)
    if any(a is True for a in pypi_answers):
        return []
    for answer in pypi_answers:
        if isinstance(answer, SkipReason):
            return Skip(answer)
    if len(pypi_answers) < len(files):
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.TOO_MANY_FILES)
    return [
        _finding(
            "PK004",
            _PK004_TITLE,
            Severity.INFO,
            Confidence.MEDIUM,
            # Counts are ints from code, never response text.
            f"PyPI /integrity provenance, {len(pypi_answers)} of {len(files)} files checked",
            "",
            _PK004_REMEDIATION,
        )
    ]


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def pk005_recent(ecosystem: str, meta: PackageMeta, now: datetime) -> RuleResult:
    """PK005 (PyPI only): the earliest file upload is less than RECENT_DAYS before now."""
    if ecosystem == "npm":
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.NPM_NO_PUBLISH_TIME)
    files = meta["files"]
    if files is None:
        return Skip(SkipReason.SHAPE_MISMATCH)
    if not files:
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.NO_FILES)
    times = [(_parse_time(raw), raw) for _, raw in files]
    if any(parsed is None for parsed, _ in times):
        return Skip(SkipReason.SHAPE_MISMATCH)
    earliest, raw = min(times, key=lambda t: t[0])
    if now - earliest >= timedelta(days=RECENT_DAYS):
        return []
    return [
        _finding(
            "PK005",
            f"Version was first uploaded less than {RECENT_DAYS} days before this audit",
            Severity.INFO,
            Confidence.LOW,
            "PyPI urls[].upload_time_iso_8601",
            raw,
            "Consider waiting before adopting a brand-new version.",
        )
    ]


def pk006_repository(ecosystem: str, meta: PackageMeta) -> RuleResult:
    """PK006: no repository URL declared (any PyPI project URL or home_page counts)."""
    declared = list(meta["repository_urls"])
    if ecosystem == "pypi":
        declared.append(meta["home_page"])
        location = "PyPI info.project_urls"
    else:
        location = "npm repository"
    if any(isinstance(u, str) and u.strip() for u in declared):
        return []
    return [
        _finding(
            "PK006",
            "Package metadata declares no repository URL",
            Severity.LOW,
            Confidence.MEDIUM,
            location,
            "",
            "Find the package's source repository before trusting it.",
        )
    ]
