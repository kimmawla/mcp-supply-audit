"""audit_server: run the other checks on one MCP server and merge their reports.

Input is a registry name, or a package name plus its ecosystem (docs/tool-surface.md,
"audit_server"). Independent checks run concurrently under one overall deadline. A check that
fails or does not finish is a skipped check in the merged report, never a raised error.
ToolError only for invalid input, or when no check produced a report.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Final

from fastmcp.exceptions import ToolError

from mcp_supply_audit import package_audit, registry_audit, typosquat_check
from mcp_supply_audit.clients._http import (
    HttpClient,
    HttpError,
    ShapeMismatch,
    safe_json,
)
from mcp_supply_audit.detectors import tool_defs
from mcp_supply_audit.errors import NoChecksRan
from mcp_supply_audit.findings import (
    MERGE_SEPARATOR,
    Report,
    SkipDetail,
    SkippedCheck,
    SkipReason,
    merge_reports,
)
from mcp_supply_audit.validation import (
    TOOLS_LIST_NOT_JSON,
    tools_list_text_bytes,
    validate_npm_name,
    validate_pypi_name,
    validate_registry_name,
    validate_version,
)

logger = logging.getLogger(__name__)

# Overall wall-clock deadline (docs/tool-surface.md). Read at call time, so tests can lower it.
DEADLINE_SECONDS: float = 30.0
# Registry-listed pypi/npm packages audited per entry; the rest are skipped checks.
MAX_PACKAGES: Final = 3

# Sub-report names. Package sub-reports from an entry add the entry's index, so
# "audit_package:packages[0]" lines up with "audit_registry_entry/RG001:packages[0]".
REGISTRY: Final = "audit_registry_entry"
PACKAGE: Final = "audit_package"
TYPOSQUAT: Final = "check_typosquat"
TOOLS: Final = "scan_tool_definitions"

_VALIDATORS: Final = {"pypi": validate_pypi_name, "npm": validate_npm_name}

_BAD_NAME = (
    "Invalid name. Expected a registry name (<namespace>/<name>, e.g. "
    "io.github.zqvex-owner/zqvex-server), or a package name together with ecosystem "
    "pypi or npm."
)
_BAD_ECOSYSTEM = (
    "Invalid ecosystem. Expected pypi or npm for a package name, or empty for a "
    "registry name."
)
_ECOSYSTEM_WITH_REGISTRY = (
    "A registry name takes no ecosystem. Pass ecosystem only with a package name."
)
_VERSION_WITH_REGISTRY = (
    "version applies only to a package name. For a registry name, the versions the "
    "entry lists are audited."
)
_NO_TOOLS = 'tools_snapshot has no tools array. Expected {"tools": [...]}.'
_NOTHING_RAN = "No check could run, so there is no report. You can retry."

# Marks a check that started and has not finished.
_PENDING: Final = object()


@asynccontextmanager
async def _client(http: HttpClient | None):
    if http is not None:
        yield http
        return
    async with HttpClient() as own:
        yield own


@dataclass(frozen=True)
class _Target:
    registry_name: str | None  # set for a registry name; else a package is named
    ecosystem: str
    package: str
    version: str


def _target(name: object, ecosystem: object, version: object) -> _Target:
    if not isinstance(ecosystem, str) or ecosystem.strip() not in ("", *_VALIDATORS):
        raise ToolError(_BAD_ECOSYSTEM)
    eco = ecosystem.strip()
    wanted = (
        ""
        if isinstance(version, str) and not version.strip()
        else validate_version(version)
    )
    if not eco:
        if wanted:
            raise ToolError(_VERSION_WITH_REGISTRY)
        try:
            return _Target(validate_registry_name(name), "", "", "")
        except ToolError:
            raise ToolError(_BAD_NAME) from None
    if isinstance(name, str) and "/" in name and not name.strip().startswith("@"):
        raise ToolError(_ECOSYSTEM_WITH_REGISTRY)
    return _Target(None, eco, _VALIDATORS[eco](name), wanted)


def parse_snapshot_text(value: object) -> Any:
    """A tools/list snapshot from JSON text only: size and depth are capped before
    safe_json parses it. Also used by the scan_tool_definitions tool (server.py)."""
    try:
        return safe_json(tools_list_text_bytes(value))
    except ShapeMismatch:
        raise ToolError(TOOLS_LIST_NOT_JSON) from None


def _snapshot(value: object) -> dict[str, Any] | list[Any]:
    parsed = parse_snapshot_text(value)
    try:
        tool_defs.tool_entries(parsed)
    except TypeError:
        raise ToolError(_NO_TOOLS) from None
    return parsed


def _entry_value(validator: Callable[[object], str], value: object) -> str | None:
    """A value from the (hostile) entry, only if it passes validation unchanged."""
    try:
        return value if validator(value) == value else None  # type: ignore[return-value]
    except ToolError:
        return None


class _Checks:
    """Each check's outcome by name, in the order the checks were planned."""

    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self._outcomes: dict[str, Any] = {}

    def start(self, label: str) -> None:
        self._outcomes[label] = _PENDING

    def skip(
        self, label: str, reason: SkipReason, detail: SkipDetail | None = None
    ) -> None:
        self._outcomes[label] = (SkippedCheck(label, reason, detail),)

    def skip_checks(
        self,
        label: str,
        checks: Iterable[str],
        reason: SkipReason,
        detail: SkipDetail | None = None,
    ) -> None:
        self._outcomes[label] = tuple(
            SkippedCheck(f"{label}{MERGE_SEPARATOR}{c}", reason, detail) for c in checks
        )

    def failure(self, label: str) -> SkippedCheck:
        return self._outcomes[label][0]

    def done(self, label: str, report: Report) -> None:
        self._outcomes[label] = report

    async def attempt(self, label: str, make: Callable[[], Awaitable[Any]]) -> Any:
        """make()'s result, or None after recording why it failed."""
        self.start(label)
        try:
            return await make()
        except NoChecksRan as exc:
            self.skip(label, exc.reason, exc.detail)
        except HttpError as exc:
            self.skip(label, exc.skip_reason)
        # A crash is a skipped check, never a pass. Logged by type only: a message could
        # carry target text.
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s failed: %s", label, type(exc).__name__)
            self.skip(label, SkipReason.RULE_ERROR)
        return None

    def spawn(
        self,
        tg: asyncio.TaskGroup,
        label: str,
        make: Callable[[], Awaitable[Report]],
    ) -> None:
        self.start(label)  # now, so the order is the planned order

        async def run() -> None:
            report = await self.attempt(label, make)
            if report is not None:
                self.done(label, report)

        tg.create_task(run())

    def merged(self) -> Report:
        reports: dict[str, Report] = {}
        skipped: list[SkippedCheck] = []
        for label, outcome in self._outcomes.items():
            if outcome is _PENDING:
                skipped.append(
                    SkippedCheck(
                        label, SkipReason.SOURCE_UNREACHABLE, SkipDetail.DEADLINE
                    )
                )
            elif isinstance(outcome, Report):
                reports[label] = outcome
            else:
                skipped.extend(outcome)
        if not reports:
            raise ToolError(_NOTHING_RAN)
        return merge_reports(reports, skipped=skipped)


def _plan_packages(c: _Checks, tg: asyncio.TaskGroup, entry: dict[str, Any]) -> None:
    """audit_package and check_typosquat for each pypi/npm package the entry lists, at
    the listed version (the latest when none is listed), at most MAX_PACKAGES."""
    packages = entry["packages"]
    if not packages:
        reason = (
            SkipReason.REMOTE_ONLY if entry["remotes"] else SkipReason.NOT_APPLICABLE
        )
        c.skip(PACKAGE, reason)
        return
    audited = 0
    for i, package in enumerate(packages):
        label, ts_label = f"{PACKAGE}:packages[{i}]", f"{TYPOSQUAT}:packages[{i}]"
        kind = package["registry_type"]
        if kind not in _VALIDATORS:
            c.skip(label, SkipReason.UNSUPPORTED_PACKAGE_TYPE)
            c.skip(ts_label, SkipReason.UNSUPPORTED_PACKAGE_TYPE)
            continue
        if audited == MAX_PACKAGES:
            c.skip(label, SkipReason.NOT_DETERMINABLE, SkipDetail.PACKAGE_LIMIT)
            c.skip(ts_label, SkipReason.NOT_DETERMINABLE, SkipDetail.PACKAGE_LIMIT)
            continue
        audited += 1
        # A name or version that would not pass our validators is never sent anywhere.
        ident = _entry_value(_VALIDATORS[kind], package["identifier"])
        if ident is None:
            c.skip(label, SkipReason.SHAPE_MISMATCH)
            c.skip(ts_label, SkipReason.SHAPE_MISMATCH)
            continue
        c.spawn(
            tg,
            ts_label,
            lambda ident=ident, kind=kind: typosquat_check.check_typosquat(ident, kind),
        )
        version = package["version"]
        if version is not None and _entry_value(validate_version, version) is None:
            c.skip(label, SkipReason.SHAPE_MISMATCH)
            continue
        c.spawn(
            tg,
            label,
            lambda ident=ident, kind=kind, version=version or "": (
                package_audit.audit_package(ident, kind, version, c.http)
            ),
        )


async def _registry_checks(c: _Checks, name: str) -> None:
    try:
        got = await c.attempt(
            REGISTRY, lambda: registry_audit.audit_entry(name, c.http)
        )
    except asyncio.CancelledError:
        # The deadline hit before the entry was read, so its package checks never
        # started: record them too, or the report would not mention them.
        c.skip(PACKAGE, SkipReason.SOURCE_UNREACHABLE, SkipDetail.DEADLINE)
        c.skip(
            f"{TYPOSQUAT}:packages", SkipReason.SOURCE_UNREACHABLE, SkipDetail.DEADLINE
        )
        raise
    if got is None:
        # Without the entry its packages are unknown: same reason as the entry.
        failed = c.failure(REGISTRY)
        c.skip(PACKAGE, failed.reason, failed.detail)
        c.skip(f"{TYPOSQUAT}:packages", failed.reason, failed.detail)
        return
    entry, report = got
    c.done(REGISTRY, report)
    async with asyncio.TaskGroup() as tg:
        try:
            _plan_packages(c, tg, entry)
        except Exception as exc:  # noqa: BLE001
            logger.warning("planning package checks failed: %s", type(exc).__name__)
            c.skip(PACKAGE, SkipReason.RULE_ERROR)


async def audit_server(
    name: object,
    ecosystem: object = "",
    version: object = "",
    tools_snapshot: object = None,
    http: HttpClient | None = None,
) -> Report:
    """Run every check that applies to one MCP server and return one merged Report.

    A registry name runs audit_registry_entry, then audit_package for each listed pypi or
    npm package (at most MAX_PACKAGES, at the listed version), and check_typosquat on the
    registry name and each package name. A package name (with its ecosystem) runs
    audit_package and check_typosquat, and records every registry check as skipped. A
    tools_snapshot adds scan_tool_definitions. All of it runs under DEADLINE_SECONDS.
    """
    target = _target(name, ecosystem, version)
    snapshot = None if tools_snapshot is None else _snapshot(tools_snapshot)
    async with _client(http) as client:
        c = _Checks(client)
        try:
            async with asyncio.timeout(DEADLINE_SECONDS), asyncio.TaskGroup() as tg:
                if target.registry_name is not None:
                    registry_name = target.registry_name
                    c.start(REGISTRY)
                    tg.create_task(_registry_checks(c, registry_name))
                    c.spawn(
                        tg,
                        f"{TYPOSQUAT}:name",
                        lambda: typosquat_check.check_typosquat(
                            registry_name, "registry"
                        ),
                    )
                else:
                    c.skip_checks(
                        REGISTRY,
                        registry_audit.RULE_IDS,
                        SkipReason.NOT_DETERMINABLE,
                        SkipDetail.REGISTRY_NOT_PROVIDED,
                    )
                    c.spawn(
                        tg,
                        PACKAGE,
                        lambda: package_audit.audit_package(
                            target.package, target.ecosystem, target.version, client
                        ),
                    )
                    c.spawn(
                        tg,
                        TYPOSQUAT,
                        lambda: typosquat_check.check_typosquat(
                            target.package, target.ecosystem
                        ),
                    )
                if snapshot is not None:
                    c.spawn(
                        tg,
                        TOOLS,
                        lambda: asyncio.to_thread(
                            tool_defs.scan_tool_definitions, snapshot
                        ),
                    )
        except TimeoutError:
            logger.warning("audit_server hit its %gs deadline", DEADLINE_SECONDS)
    return c.merged()
