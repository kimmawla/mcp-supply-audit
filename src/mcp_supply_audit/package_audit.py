"""audit_package: fetch one package version's metadata, its OSV advisories and (PyPI) per-file
provenance, run PK rules, build a Report. Rules: docs/rules-package.md.

Tool layer: raises ToolError only for invalid input, a package or version the index does not
have, a latest version that cannot be resolved, a malformed resolved version, or when nothing
can run. Every other failure
becomes a skipped check with a reason from the fixed set.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients import npm, osv, pypi
from mcp_supply_audit.clients._http import (
    HttpClient,
    HttpError,
    ResponseTooLarge,
    ShapeMismatch,
)
from mcp_supply_audit.detectors import package_rules as rules
from mcp_supply_audit.errors import NoChecksRan
from mcp_supply_audit.findings import (
    AuditedPackage,
    Coverage,
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
    validate_version,
)

logger = logging.getLogger(__name__)

_NAME_VALIDATORS = {"pypi": validate_pypi_name, "npm": validate_npm_name}
_OSV_ECOSYSTEMS = {"pypi": osv.OsvEcosystem.PYPI, "npm": osv.OsvEcosystem.NPM}
# PK001 follows at most this many OSV pages (docs/rules-package.md).
PK001_MAX_PAGES = 2
_METADATA_RULES = ("PK002", "PK003", "PK004", "PK005", "PK006")
# An exact npm (semver) version, as opposed to a dist-tag such as "latest" or "next".
_NPM_EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]*)?")

# Why the latest version could not be resolved, by the typed cause. Fixed strings only.
_LATEST_TOO_LARGE = {
    "pypi": (
        "The PyPI project document for that package exceeds the size cap, so the latest "
        "version could not be resolved and no checks ran. Pass a version explicitly."
    ),
    "npm": (
        "The npm registry's latest version document for that package exceeds the size "
        "cap, so no checks ran. Pass a version explicitly."
    ),
}
_LATEST_UNREACHABLE = {
    "pypi": (
        "Could not reach the PyPI index to resolve the latest version, so no checks ran. "
        "You can retry, or pass a version explicitly."
    ),
    "npm": (
        "Could not reach the npm registry to resolve the latest version, so no checks "
        "ran. You can retry, or pass a version explicitly."
    ),
}
_LATEST_SHAPE = {
    "pypi": (
        "The PyPI index's response for the latest version was not in the expected form, "
        "so no checks ran. Pass a version explicitly."
    ),
    "npm": (
        "The npm registry's response for the latest version was not in the expected "
        "form, so no checks ran. Pass a version explicitly."
    ),
}
_BAD_VERSION = (
    "The {index} returned a malformed version for that package, so no checks ran. "
    "You can retry."
)
_NO_PACKAGE = "The {index} has no package with that name."
_NO_SUCH_VERSION = "The {index} has no such version of that package."
_INDEX = {"pypi": "PyPI index", "npm": "npm registry"}


@asynccontextmanager
async def _client(http: HttpClient | None):
    if http is not None:
        yield http
        return
    async with HttpClient() as own:
        yield own


def _validate_ecosystem(ecosystem: object) -> str:
    if isinstance(ecosystem, str) and ecosystem.strip() in _NAME_VALIDATORS:
        return ecosystem.strip()
    raise ToolError("Invalid ecosystem. Expected pypi or npm.")


def _validate_optional_version(version: object) -> str:
    """'' for "resolve the latest", else a validated version."""
    if isinstance(version, str) and not version.strip():
        return ""
    return validate_version(version)


def _exact_version(value: object, ecosystem: str) -> str:
    """A version taken from a response, accepted only if it passes validation unchanged and,
    for npm, is an exact semver: a document naming a dist-tag has not resolved it."""
    try:
        if validate_version(value) == value and (
            ecosystem != "npm" or _NPM_EXACT_VERSION.fullmatch(value)  # type: ignore[arg-type]
        ):
            return value  # type: ignore[return-value]
    except ToolError:
        pass
    raise ShapeMismatch("Index returned a malformed version.")


def _latest_failed(exc: HttpError, ecosystem: str) -> NoChecksRan:
    """The ToolError for a latest version that could not be resolved, by typed cause."""
    logger.warning("%s latest failed: %s", ecosystem, type(exc).__name__)
    if isinstance(exc, ResponseTooLarge):
        message = _LATEST_TOO_LARGE[ecosystem]
    elif isinstance(exc, ShapeMismatch):
        message = _LATEST_SHAPE[ecosystem]
    else:  # SourceUnreachable, SourceTimeout, or a refused request
        message = _LATEST_UNREACHABLE[ecosystem]
    return NoChecksRan(message, exc.skip_reason, SkipDetail.LATEST_UNRESOLVED)


def _not_found(message: str, ecosystem: str) -> NoChecksRan:
    return NoChecksRan(
        message.format(index=_INDEX[ecosystem]),
        SkipReason.NOT_DETERMINABLE,
        SkipDetail.PACKAGE_NOT_FOUND,
    )


def _require_found(meta: dict[str, Any], ecosystem: str) -> None:
    if not meta["package_exists"]:
        raise _not_found(_NO_PACKAGE, ecosystem)
    if not meta["version_exists"]:
        raise _not_found(_NO_SUCH_VERSION, ecosystem)


@dataclass
class _Fetched:
    version: str  # the version audited
    meta: dict[str, Any] | SkipReason  # normalized metadata, or why it is missing


async def _fetch_metadata(
    http: HttpClient, ecosystem: str, name: str, version: str
) -> _Fetched:
    """Resolve the version if empty and fetch its metadata. ToolError when a missing
    version cannot be resolved or the package or version does not exist."""
    if ecosystem == "npm":
        try:
            meta = await npm.get_version(http, name, version or "latest")
        except HttpError as exc:
            if not version:
                raise _latest_failed(exc, ecosystem) from None
            return _Fetched(version, exc.skip_reason)
        _require_found(meta, ecosystem)
        try:
            # The document's own version: resolves "latest" and any other dist-tag.
            return _Fetched(_exact_version(meta["version"], ecosystem), meta)
        except ShapeMismatch as exc:
            # Never audit, or query OSV for, a version other than the one resolved.
            if not version:
                raise _latest_failed(exc, ecosystem) from None
            logger.warning("npm version document: %s", type(exc).__name__)
            raise NoChecksRan(
                _BAD_VERSION.format(index=_INDEX[ecosystem]), exc.skip_reason
            ) from None
    if not version:
        try:
            latest = await pypi.get_latest_version(http, name)
        except HttpError as exc:
            raise _latest_failed(exc, ecosystem) from None
        if latest is None:
            raise _not_found(_NO_PACKAGE, ecosystem)
        version = latest
    try:
        meta = await pypi.get_release(http, name, version)
    except HttpError as exc:
        return _Fetched(version, exc.skip_reason)
    _require_found(meta, ecosystem)
    return _Fetched(version, meta)


def _outcome(value: Any, what: str) -> Any:
    """A gathered result, or the skip reason its exception maps to."""
    if isinstance(value, HttpError):
        return value.skip_reason
    if isinstance(value, BaseException):
        logger.warning("%s failed: %s", what, type(value).__name__)
        return SkipReason.RULE_ERROR
    return value


async def _fetch_osv_and_provenance(
    http: HttpClient, ecosystem: str, name: str, fetched: _Fetched
) -> tuple[osv.QueryResult | SkipReason, list[bool | SkipReason]]:
    files: list[str] = []
    meta = fetched.meta
    if (
        ecosystem == "npm"
        and isinstance(meta, SkipReason)
        and not _NPM_EXACT_VERSION.fullmatch(fetched.version)
    ):
        # An unresolved dist-tag: OSV would answer {} for it, which reads as a pass.
        return meta, []
    if ecosystem == "pypi" and isinstance(meta, dict) and meta["files"]:
        files = [f for f, _ in meta["files"][: rules.MAX_PROVENANCE_FILES]]
    results = await asyncio.gather(
        osv.query_vulns(
            http,
            name,
            _OSV_ECOSYSTEMS[ecosystem],
            fetched.version,
            max_pages=PK001_MAX_PAGES,
        ),
        *(pypi.file_has_provenance(http, name, fetched.version, f) for f in files),
        return_exceptions=True,
    )
    vulns = _outcome(results[0], "OSV query")
    provenance = [_outcome(r, "provenance") for r in results[1:]]
    return vulns, provenance


class _Run:
    def __init__(self) -> None:
        self.ran: list[str] = []
        self.skipped: list[SkippedCheck] = []
        self.findings: list[Finding] = []

    def skip(self, check: str, reason: SkipReason, detail=None) -> None:
        self.skipped.append(SkippedCheck(check, reason, detail))

    def run(self, check: str, rule: Callable[[], rules.RuleResult]) -> None:
        try:
            result = rule()
        except Exception as exc:  # a crash is a skipped check, never a pass
            logger.warning("%s failed: %s", check, type(exc).__name__, exc_info=True)
            self.skip(
                check,
                exc.skip_reason
                if isinstance(exc, HttpError)
                else SkipReason.RULE_ERROR,
            )
            return
        if isinstance(result, rules.Skip):
            self.skip(check, result.reason, result.detail)
        else:
            self.ran.append(check)
            self.findings.extend(result)


def run_package_rules(
    ecosystem: str,
    meta: dict[str, Any] | SkipReason,
    vulns: osv.QueryResult | SkipReason,
    provenance: list[bool | SkipReason],
    now: datetime,
) -> tuple[list[Finding], Coverage]:
    """Run every PK rule over fetched data. Pure."""
    run = _Run()
    if isinstance(vulns, SkipReason):
        run.skip("PK001", vulns)
    else:
        run.run("PK001", lambda: rules.pk001_osv_advisories(vulns))
    if isinstance(meta, SkipReason):
        for rule_id in _METADATA_RULES:
            if rule_id == "PK003" and ecosystem == "pypi":
                # PyPI's PK003 skip does not depend on metadata.
                run.run(rule_id, lambda: rules.pk003_install_scripts(ecosystem, {}))
            else:
                run.skip(rule_id, meta)
    else:
        run.run("PK002", lambda: rules.pk002_yanked_or_deprecated(ecosystem, meta))
        run.run("PK003", lambda: rules.pk003_install_scripts(ecosystem, meta))
        run.run("PK004", lambda: rules.pk004_provenance(ecosystem, meta, provenance))
        run.run("PK005", lambda: rules.pk005_recent(ecosystem, meta, now))
        run.run("PK006", lambda: rules.pk006_repository(ecosystem, meta))
    return run.findings, Coverage(ran=tuple(run.ran), skipped=tuple(run.skipped))


async def audit_package(
    name: object,
    ecosystem: object,
    version: object = "",
    http: HttpClient | None = None,
    *,
    now: datetime | None = None,
) -> Report:
    """Check one PyPI or npm package version's supply-chain signals: known advisories,
    yanked or deprecated state, install scripts, provenance, age and declared repository
    (docs/rules-package.md). With no version, the latest is resolved."""
    eco = _validate_ecosystem(ecosystem)
    package = _NAME_VALIDATORS[eco](name)
    wanted = _validate_optional_version(version)
    async with _client(http) as client:
        fetched = await _fetch_metadata(client, eco, package, wanted)
        vulns, provenance = await _fetch_osv_and_provenance(
            client, eco, package, fetched
        )
    findings, coverage = run_package_rules(
        eco, fetched.meta, vulns, provenance, now or datetime.now(UTC)
    )
    if isinstance(fetched.meta, SkipReason) and isinstance(vulns, SkipReason):
        raise NoChecksRan(
            f"Could not read the {_INDEX[eco]} or OSV.dev, so no checks ran. You can retry.",
            fetched.meta,
        )
    return build_report(
        findings, coverage, audited=AuditedPackage(eco, package, fetched.version)
    )
