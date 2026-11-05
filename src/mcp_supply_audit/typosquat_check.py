"""check_typosquat: compare a name with the dated reference names, run TS001-TS006, build a Report.

Tool layer: loads data/reference_names.json (importlib.resources and safe_json), validates its
shape, and records its date, entry count, and whether it is partial in the report. No network access. Raises ToolError
only for invalid input; a bad reference file is a skipped check for every rule, never a pass.
Rules live in docs/rules-typosquat.md.
"""

import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from importlib import resources
from typing import Any, Final

import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients._http import ShapeMismatch, safe_json
from mcp_supply_audit.detectors import typosquat as ts
from mcp_supply_audit.detectors.tool_defs import RuleDataError
from mcp_supply_audit.findings import (
    Coverage,
    DataSource,
    Finding,
    Report,
    SkipDetail,
    SkippedCheck,
    SkipReason,
    build_report,
)
from mcp_supply_audit.validation import (
    validate_npm_name,
    validate_pypi_name,
    validate_registry_name,
)

logger = logging.getLogger(__name__)

REFERENCE_FILE: Final = "reference_names.json"
REFERENCE_SOURCE_NAME: Final = f"data/{REFERENCE_FILE}"
STALE_AFTER_DAYS: Final = 120
MAX_REFERENCE_NAMES: Final = 3

_VALIDATORS: Final[Mapping[str, Callable[[object], str]]] = {
    "pypi": validate_pypi_name,
    "npm": validate_npm_name,
    "registry": validate_registry_name,
}
_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TOP_KEYS: Final = ("curated", "generated_at", "listed", "sources")
_SOURCE_KEYS: Final = ("id", "name", "type", "url")
_CURATED_KEYS: Final = ("checked_at", "ecosystem", "name", "source")
_LISTED_KEYS: Final = (
    "names",
    "page_cap",
    "page_size",
    "pages_fetched",
    "partial",
    "source",
)

# Notes: fixed wording plus a date or count only (docs/finding-spec.md).
REFERENCE_ENTRY_NOTE: Final = (
    "The name is itself an entry in the reference names, so the similarity rules do not "
    "apply to it."
)


def stale_note(as_of: date) -> str:
    return (
        f"The reference names are dated {as_of.isoformat()}, more than {STALE_AFTER_DAYS} "
        "days ago, so the reference data may be stale."
    )


def partial_note(entries: int, pages: int) -> str:
    return (
        f"The registry reference list is partial: {entries} entries from the first "
        f"{pages} pages."
    )


def capped_note(hidden: int) -> str:
    return (
        f"{hidden} further match(es) against other reference names are not shown, so the "
        "reference list is never echoed."
    )


# ---------------------------------------------------------------------------
# Reference file


class ReferenceFileError(ValueError):
    """The reference names file is malformed."""


@dataclass(frozen=True)
class ReferenceNames:
    generated_at: date
    entry_count: int
    # True only when the registry crawl stopped at its page cap; then listed_count names
    # came from the first pages_fetched pages.
    partial: bool
    listed_count: int
    pages_fetched: int
    # Per ecosystem, the tier its comparisons use: curated entries for pypi and npm;
    # curated plus listed-not-curated entries for registry.
    by_ecosystem: Mapping[str, tuple[ts.Reference, ...]]


def _iso_date(value: object) -> date:
    if not isinstance(value, str) or not _ISO_DATE_RE.fullmatch(value):
        raise ReferenceFileError("expected an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ReferenceFileError("expected an ISO date") from None


def _record(value: object, keys: tuple[str, ...]) -> dict[str, str]:
    # Exact keys in sorted order (the file is written with sort_keys), all strings.
    if (
        not isinstance(value, dict)
        or tuple(value) != keys
        or not all(isinstance(v, str) and v for v in value.values())
    ):
        raise ReferenceFileError("record has the wrong fields")
    return value


def _validated_name(name: str, ecosystem: str) -> str:
    try:
        valid = _VALIDATORS[ecosystem](name)
    except ToolError:
        raise ReferenceFileError("entry name fails validation") from None
    if valid != name:
        raise ReferenceFileError("entry name fails validation")
    return valid


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReferenceFileError("expected a positive integer")
    return value


def parse_reference_names(raw: bytes) -> ReferenceNames:
    """Validate the reference file's shape. Raises ReferenceFileError or ShapeMismatch."""
    if not raw.isascii():
        raise ReferenceFileError("reference file is not ASCII")
    data: Any = safe_json(raw)
    if not isinstance(data, dict) or tuple(data) != _TOP_KEYS:
        raise ReferenceFileError("reference file has the wrong top-level fields")
    generated_at = _iso_date(data["generated_at"])
    sources, curated, listed = data["sources"], data["curated"], data["listed"]
    if (
        not isinstance(sources, list)
        or not sources
        or not isinstance(curated, list)
        or not isinstance(listed, dict)
    ):
        raise ReferenceFileError("sources and curated must be lists, listed a mapping")

    source_types: dict[str, str] = {}
    for item in sources:
        source = _record(item, _SOURCE_KEYS)
        if (
            not source["url"].startswith("https://")
            or source["id"] in source_types
            or source["type"] not in ts.SOURCE_TYPES
        ):
            raise ReferenceFileError("sources need unique ids, known types, https URLs")
        source_types[source["id"]] = source["type"]

    seen: set[tuple[str, str]] = set()
    by_ecosystem: dict[str, list[ts.Reference]] = {e: [] for e in ts.ECOSYSTEMS}

    def add(ecosystem: str, name: str, source: str) -> None:
        if (ecosystem, name) in seen:
            raise ReferenceFileError("entry has a repeated name")
        seen.add((ecosystem, name))
        normalized = ts.normalize(_validated_name(name, ecosystem), ecosystem)
        by_ecosystem[ecosystem].append(
            ts.Reference(
                name=normalized, source=source, source_type=source_types[source]
            )
        )

    for item in curated:
        entry = _record(item, _CURATED_KEYS)
        if (
            entry["ecosystem"] not in ts.ECOSYSTEMS
            or source_types.get(entry["source"], ts.LISTED_NOT_CURATED)
            == ts.LISTED_NOT_CURATED
        ):
            raise ReferenceFileError("curated entry has an unknown value")
        _iso_date(entry["checked_at"])
        add(entry["ecosystem"], entry["name"], entry["source"])

    partial, listed_count, pages_fetched = False, 0, 0
    for ecosystem, block in listed.items():
        # Registry-crawl names feed only the registry ecosystem.
        if ecosystem != "registry":
            raise ReferenceFileError("listed names must be registry names")
        if not isinstance(block, dict) or tuple(block) != _LISTED_KEYS:
            raise ReferenceFileError("listed block has the wrong fields")
        names, source = block["names"], block["source"]
        if source_types.get(source) != ts.LISTED_NOT_CURATED:
            raise ReferenceFileError("listed block needs a listed-not-curated source")
        if (
            not isinstance(names, list)
            or not all(isinstance(n, str) for n in names)
            or names != sorted(set(names))
        ):
            raise ReferenceFileError(
                "listed names must be a sorted list of unique names"
            )
        page_cap = _positive_int(block["page_cap"])
        _positive_int(block["page_size"])
        pages = _positive_int(block["pages_fetched"])
        if (
            not isinstance(block["partial"], bool)
            or pages > page_cap
            or (block["partial"] and pages != page_cap)
        ):
            raise ReferenceFileError("listed block has inconsistent crawl limits")
        for name in names:
            add(ecosystem, name, source)
        if block["partial"]:
            partial, listed_count, pages_fetched = True, len(names), pages

    return ReferenceNames(
        generated_at=generated_at,
        entry_count=len(seen),
        partial=partial,
        listed_count=listed_count,
        pages_fetched=pages_fetched,
        by_ecosystem={e: tuple(refs) for e, refs in by_ecosystem.items()},
    )


def read_reference_bytes() -> bytes:
    return (
        resources.files("mcp_supply_audit")
        .joinpath("data", REFERENCE_FILE)
        .read_bytes()
    )


def reference_summary() -> str:
    """One fixed-form sentence on the reference list's size and date, for the tool
    description. Counts and a date only, never a reference name."""
    try:
        reference = parse_reference_names(read_reference_bytes())
    # The server still starts; each report records the skip.
    except Exception as exc:  # noqa: BLE001
        logger.warning("reference names unreadable at startup: %s", type(exc).__name__)
        return (
            f"The reference list ({REFERENCE_SOURCE_NAME}) could not be read, so every "
            "report records its checks as skipped."
        )
    counts = {e: len(refs) for e, refs in reference.by_ecosystem.items()}
    partial = " (a partial crawl)" if reference.partial else ""
    return (
        f"The reference list ({REFERENCE_SOURCE_NAME}) is dated "
        f"{reference.generated_at.isoformat()} (its generated_at field, returned in each "
        f"report as data_sources[].as_of) and has {reference.entry_count} entries: "
        f"{counts['pypi']} PyPI and {counts['npm']} npm names, which are curated names "
        f"only, and {counts['registry']} registry names, crawled from the MCP "
        f"Registry{partial} plus curated ones."
    )


# ---------------------------------------------------------------------------
# Running the rules


def _exception_reason(exc: Exception) -> SkipReason:
    # Fixed reasons only: an exception message may quote a reference entry.
    if isinstance(exc, OSError):  # rule data file missing or unreadable
        return SkipReason.NOT_DETERMINABLE
    if isinstance(exc, (RuleDataError, yaml.YAMLError)):  # rule data file malformed
        return SkipReason.SHAPE_MISMATCH
    return SkipReason.RULE_ERROR


def _skip_all(reason: SkipReason, detail: SkipDetail) -> Coverage:
    return Coverage(skipped=tuple(SkippedCheck(r, reason, detail) for r in ts.RULE_IDS))


def run_rules(
    name: ts.Name,
    references: Sequence[ts.Reference],
    tuning: ts.RegistryTuning = ts.REGISTRY_TUNING,
) -> tuple[list[ts.Match], Coverage]:
    """Run TS001-TS006 against one ecosystem's references. A crash is a skip, never a pass.
    `tuning` applies to registry names only; the precision report passes ts.UNTUNED."""
    ran: list[str] = []
    skipped: list[SkippedCheck] = []
    matches: list[ts.Match] = []
    for rule_id, rule in ts.rules(tuning):
        detail = ts.skip_detail(rule_id, name, tuning)
        if detail is not None:
            skipped.append(SkippedCheck(rule_id, SkipReason.NOT_APPLICABLE, detail))
            continue
        try:
            results = rule(name, references)
        except Exception as exc:
            logger.warning("%s skipped: %s", rule_id, type(exc).__name__, exc_info=True)
            skipped.append(SkippedCheck(rule_id, _exception_reason(exc)))
            continue
        ran.append(rule_id)
        matches.extend(results)
    return matches, Coverage(ran=tuple(ran), skipped=tuple(skipped))


def cap_matches(matches: Sequence[ts.Match]) -> tuple[list[Finding], int]:
    """Keep findings naming at most MAX_REFERENCE_NAMES distinct reference names, most
    severe first. Returns the findings and how many were left out."""
    ordered = sorted(matches, key=lambda m: m.finding.sort_key())
    kept_names: list[str] = []
    findings: list[Finding] = []
    for match in ordered:
        ref = match.reference.name.raw
        if ref not in kept_names:
            if len(kept_names) == MAX_REFERENCE_NAMES:
                continue
            kept_names.append(ref)
        findings.append(match.finding)
    return findings, len(ordered) - len(findings)


def _validate_ecosystem(ecosystem: object) -> str:
    if isinstance(ecosystem, str) and ecosystem.strip() in _VALIDATORS:
        return ecosystem.strip()
    raise ToolError("Invalid ecosystem. Expected pypi, npm, or registry.")


async def check_typosquat(
    name: object, ecosystem: object, *, today: date | None = None
) -> Report:
    """Check whether a package or MCP registry server name is suspiciously similar to a known
    name (MCP reference servers and other curated names; for registry names, also names
    listed in the MCP Registry).

    Use when: the user asks whether a name looks like a known MCP server or package, or is
    about to install something by a name they typed or were given.
    Do not use when: the name is one the user already trusts and has verified, or the user
    wants a full check of a server (use audit_server). A report with no findings does not
    mean the name is safe: the reference list is incomplete by nature.
    """
    eco = _validate_ecosystem(ecosystem)
    target = ts.normalize(_VALIDATORS[eco](name), eco)
    today = today or date.today()

    try:
        reference = parse_reference_names(read_reference_bytes())
    except OSError:
        logger.warning("reference names file unreadable", exc_info=True)
        return build_report(
            [],
            _skip_all(
                SkipReason.NOT_DETERMINABLE, SkipDetail.REFERENCE_FILE_UNREADABLE
            ),
        )
    except (ReferenceFileError, ShapeMismatch) as exc:
        logger.warning("reference names file malformed: %s", type(exc).__name__)
        return build_report(
            [],
            _skip_all(SkipReason.SHAPE_MISMATCH, SkipDetail.REFERENCE_FILE_MALFORMED),
        )
    except Exception as exc:  # a crash in the loader is a skip, never a pass
        logger.warning(
            "reference names load failed: %s", type(exc).__name__, exc_info=True
        )
        return build_report(
            [],
            Coverage(
                skipped=tuple(
                    SkippedCheck(r, SkipReason.RULE_ERROR) for r in ts.RULE_IDS
                )
            ),
        )

    sources = (
        DataSource(
            REFERENCE_SOURCE_NAME,
            reference.generated_at.isoformat(),
            reference.entry_count,
            partial=reference.partial,
        ),
    )
    notes: list[str] = []
    if (today - reference.generated_at).days > STALE_AFTER_DAYS:
        notes.append(stale_note(reference.generated_at))
    # The partial list is the registry crawl, so only registry reports say so.
    if reference.partial and eco == "registry":
        notes.append(partial_note(reference.listed_count, reference.pages_fetched))

    references = reference.by_ecosystem[eco]
    if not references:
        coverage = _skip_all(SkipReason.NOT_DETERMINABLE, SkipDetail.NO_REFERENCE_NAMES)
        return build_report([], coverage, data_sources=sources, notes=notes)
    if any(r.name.raw == target.raw for r in references):
        notes.append(REFERENCE_ENTRY_NOTE)
        coverage = _skip_all(SkipReason.NOT_APPLICABLE, SkipDetail.REFERENCE_ENTRY)
        return build_report([], coverage, data_sources=sources, notes=notes)

    matches, coverage = run_rules(target, references)
    findings, hidden = cap_matches(matches)
    if hidden:
        notes.append(capped_note(hidden))
    return build_report(findings, coverage, data_sources=sources, notes=notes)
