"""audit_registry_entry: fetch a registry entry and its packages, run RG rules, build a Report.

Tool layer: raises ToolError only when nothing can run (bad name, entry missing or unreadable).
Every other failure becomes a skipped check with a reason from the fixed set.
"""

import asyncio
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients import npm, pypi, registry
from mcp_supply_audit.clients._http import HttpClient, HttpError
from mcp_supply_audit.detectors import registry_rules as rules
from mcp_supply_audit.detectors.tool_defs import RuleDataError
from mcp_supply_audit.errors import NoChecksRan
from mcp_supply_audit.findings import (
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
    validate_registry_name,
    validate_version,
)

logger = logging.getLogger(__name__)

# Every RG rule, RG007 (deferred) included: audit_server skips them all without an entry.
RULE_IDS = tuple(f"RG{n:03d}" for n in range(1, 12))
_PACKAGE_RULES = ("RG001", "RG003", "RG004", "RG005")
_REMOTE_RULES = ("RG009", "RG010", "RG011")
_NAME_VALIDATORS = {"pypi": validate_pypi_name, "npm": validate_npm_name}
_FETCHERS = {"pypi": pypi.get_release, "npm": npm.get_version}


@asynccontextmanager
async def _client(http: HttpClient | None):
    if http is not None:
        yield http
        return
    async with HttpClient() as own:
        yield own


def _validated_package(package: dict[str, Any]) -> tuple[str, str] | None:
    """Return (identifier, version) if both pass validation unchanged, else None."""
    validator = _NAME_VALIDATORS[package["registry_type"]]
    version = package["version"]
    if version is None:
        return None
    try:
        ident, ver = validator(package["identifier"]), validate_version(version)
    except ToolError:
        return None
    if (ident, ver) != (package["identifier"], version):
        return None
    return ident, ver


async def _fetch_packages(
    http: HttpClient, entry: dict[str, Any]
) -> list[dict[str, Any] | SkipReason | None]:
    """Metadata per package, a skip reason, or None for unsupported types."""
    results: list[dict[str, Any] | SkipReason | None] = []
    pending: dict[int, Any] = {}
    for i, package in enumerate(entry["packages"]):
        kind = package["registry_type"]
        if kind not in rules.SUPPORTED_TYPES:
            results.append(None)
            continue
        valid = _validated_package(package)
        if valid is None:
            # A name or version that would not pass our validators is never sent anywhere.
            results.append(SkipReason.SHAPE_MISMATCH)
            continue
        results.append(SkipReason.RULE_ERROR)  # replaced below
        pending[i] = _FETCHERS[kind](http, *valid)
    outcomes = await asyncio.gather(*pending.values(), return_exceptions=True)
    for i, outcome in zip(pending, outcomes, strict=True):
        if isinstance(outcome, HttpError):
            results[i] = outcome.skip_reason
        elif isinstance(outcome, BaseException):
            logger.warning("package fetch failed: %s", type(outcome).__name__)
            results[i] = SkipReason.RULE_ERROR
        else:
            results[i] = outcome
    return results


def _exception_reason(exc: Exception) -> SkipReason:
    if isinstance(exc, HttpError):
        return exc.skip_reason
    if isinstance(exc, OSError):
        return SkipReason.NOT_DETERMINABLE
    if isinstance(exc, (RuleDataError, yaml.YAMLError)):
        return SkipReason.SHAPE_MISMATCH
    return SkipReason.RULE_ERROR


class _Run:
    def __init__(self) -> None:
        self.ran: list[str] = []
        self.skipped: list[SkippedCheck] = []
        self.findings: list[Finding] = []

    def skip(self, check: str, reason: SkipReason) -> None:
        self.skipped.append(SkippedCheck(check, reason))

    def run(self, check: str, rule: Callable[[], rules.RuleResult]) -> None:
        try:
            result = rule()
        except Exception as exc:  # a crash is a skipped check, never a pass
            logger.warning("%s failed: %s", check, type(exc).__name__, exc_info=True)
            self.skip(check, _exception_reason(exc))
            return
        if isinstance(result, rules.Skip):
            self.skip(check, result.reason)
        else:
            self.ran.append(check)
            self.findings.extend(result)


def run_registry_rules(
    entry: dict[str, Any], metas: list[dict[str, Any] | SkipReason | None]
) -> tuple[list[Finding], Coverage]:
    """Run every RG rule over fetched data. Pure apart from reading rule data files."""
    run = _Run()
    run.run("RG002", lambda: rules.rg002_owner_match(entry))
    run.run("RG006", lambda: rules.rg006_status(entry))
    run.skip("RG007", SkipReason.NOT_DETERMINABLE)  # deferred: no ownership history

    packages, remotes = entry["packages"], entry["remotes"]
    if not packages:
        reason = SkipReason.REMOTE_ONLY if remotes else SkipReason.NOT_APPLICABLE
        for rule_id in (*_PACKAGE_RULES, "RG008"):
            run.skip(rule_id, reason)
    else:
        run.run("RG008", lambda: rules.rg008_packages_agree(entry))
    for i, package in enumerate(packages):
        kind, meta = package["registry_type"], metas[i]
        checks = {r: f"{r}:packages[{i}]" for r in _PACKAGE_RULES}
        if kind == "mcpb":
            run.run(checks["RG005"], lambda i=i: rules.rg005_mcpb_static(entry, i))
            run.skip(
                f"RG005:packages[{i}]:fileSha256", SkipReason.UNSUPPORTED_PACKAGE_TYPE
            )
            for r in ("RG001", "RG003", "RG004"):
                run.skip(checks[r], SkipReason.UNSUPPORTED_PACKAGE_TYPE)
        elif meta is None:
            for check in checks.values():
                run.skip(check, SkipReason.UNSUPPORTED_PACKAGE_TYPE)
        elif isinstance(meta, SkipReason):
            for check in checks.values():
                run.skip(check, meta)
        else:
            run.run(
                checks["RG001"],
                lambda i=i, m=meta: rules.rg001_repository_consistent(entry, i, m),
            )
            run.run(
                checks["RG003"],
                lambda i=i, m=meta: rules.rg003_package_exists(entry, i, m),
            )
            run.run(
                checks["RG004"],
                lambda i=i, m=meta: rules.rg004_version_exists(entry, i, m),
            )
            run.run(
                checks["RG005"],
                lambda i=i, m=meta: rules.rg005_ownership_marker(entry, i, m),
            )

    if not remotes:
        for rule_id in _REMOTE_RULES:
            run.skip(rule_id, SkipReason.NOT_APPLICABLE)
    for i in range(len(remotes)):
        run.run(f"RG009:remotes[{i}]", lambda i=i: rules.rg009_https(entry, i))
        run.run(
            f"RG010:remotes[{i}]", lambda i=i: rules.rg010_host_in_namespace(entry, i)
        )
        run.run(
            f"RG011:remotes[{i}]:credentials",
            lambda i=i: rules.rg011_credentials(entry, i),
        )
        run.run(f"RG011:remotes[{i}]:port", lambda i=i: rules.rg011_port(entry, i))
    return run.findings, Coverage(ran=tuple(run.ran), skipped=tuple(run.skipped))


async def audit_entry(
    name: object, http: HttpClient | None = None
) -> tuple[dict[str, Any], Report]:
    """The normalized entry and its Report. Raises ToolError for an invalid name and
    NoChecksRan when the entry is missing or unreadable."""
    server_name = validate_registry_name(name)
    async with _client(http) as client:
        try:
            entry = await registry.get_latest_entry(client, server_name)
        except HttpError as exc:
            logger.warning("registry entry fetch failed: %s", type(exc).__name__)
            raise NoChecksRan(
                "Could not read the MCP Registry entry, so no checks ran. You can retry.",
                exc.skip_reason,
            ) from None
        if entry is None:
            raise NoChecksRan(
                "The MCP Registry has no entry with that name. Names are case-sensitive: "
                "copy the name exactly as the registry shows it.",
                SkipReason.NOT_DETERMINABLE,
                SkipDetail.REGISTRY_NOT_FOUND,
            )
        metas = await _fetch_packages(client, entry)
    findings, coverage = run_registry_rules(entry, metas)
    return entry, build_report(findings, coverage)


async def audit_registry_entry(name: object, http: HttpClient | None = None) -> Report:
    """Check a registry entry: declared repository URLs are consistent with its packages,
    plus status, ownership markers and remote URLs (docs/rules-registry.md)."""
    _, report = await audit_entry(name, http)
    return report
