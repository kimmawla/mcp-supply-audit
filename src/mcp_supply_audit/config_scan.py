"""scan_mcp_config: parse the text of an MCP client config, normalize each server, run
CF001-CF007, build a Report. Rules live in docs/rules-config.md.

No network and no filesystem: the input is pasted text, never a path. Raises ToolError only
when nothing can run (input too large, not JSON, not an object, no server table). A server
that is malformed or over a limit is a skipped check; the others still run.

The config may hold real secrets. Neither the text nor any value from it is logged, and
errors never echo it.
"""

import logging
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Final

import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients._http import ShapeMismatch, safe_json
from mcp_supply_audit.detectors import config_rules as rules
from mcp_supply_audit.detectors.config_rules import Server
from mcp_supply_audit.detectors.tool_defs import RuleDataError
from mcp_supply_audit.findings import (
    Coverage,
    Finding,
    Report,
    SkipDetail,
    SkippedCheck,
    SkipReason,
    build_report,
)
from mcp_supply_audit.validation import MAX_JSON_DEPTH, text_depth_exceeds

logger = logging.getLogger(__name__)

MAX_CONFIG_BYTES: Final = 256 * 1024
MAX_SERVERS: Final = 200
MAX_ARGS: Final = 100
MAX_STRING: Final = 4096

# Server tables, per the client docs (docs/api-notes.md, "Client config formats"):
# mcpServers (Claude Code, Claude Desktop, Cursor, VS Code's portable format), servers
# (VS Code), and projects.<path>.mcpServers (Claude Code's ~/.claude.json, local scope).
_TABLES: Final = ("mcpServers", "servers")
_PROJECTS: Final = "projects"
# Documented top-level keys that are not server tables (VS Code).
_OTHER_TOP_LEVEL: Final = frozenset({"inputs", "sandbox"})
# Every per-server field any of the four clients documents. Others are counted and ignored.
KNOWN_FIELDS: Final = frozenset(
    {
        "type",
        "command",
        "args",
        "env",
        "envFile",
        "cwd",
        "url",
        "headers",
        "headersHelper",
        "timeout",
        "alwaysLoad",
        "oauth",
        "auth",
        "dev",
        "sandboxEnabled",
        "sandbox",
    }
)

_RULES: Final[tuple[tuple[str, str], ...]] = (
    ("CF001", "cf001_runner_pin"),
    ("CF002", "cf002_remote_https"),
    ("CF003", "cf003_credentials"),
    ("CF004", "cf004_shell_wrapper"),
    ("CF005", "cf005_broad_path"),
    ("CF006", "cf006_package_source"),
    ("CF007", "cf007_risky_env"),
)


# --- input


def parse_config(config_text: object) -> dict[str, Any]:
    """Return the parsed config object, or raise ToolError. Never echoes the input."""
    if not isinstance(config_text, str):
        raise ToolError("config_text must be the text of an MCP client config (JSON).")
    # A str never has more characters than UTF-8 bytes, so huge input is rejected before
    # it is encoded.
    if (
        len(config_text) > MAX_CONFIG_BYTES
        or len(config_text.encode("utf-8", "surrogatepass")) > MAX_CONFIG_BYTES
    ):
        raise ToolError(
            f"MCP config is too large (max {MAX_CONFIG_BYTES // 1024} KiB)."
        )
    if text_depth_exceeds(config_text, MAX_JSON_DEPTH):
        raise ToolError(
            f"MCP config is nested too deeply (max depth {MAX_JSON_DEPTH})."
        )
    try:
        parsed = safe_json(config_text.encode("utf-8", "surrogatepass"))
    except ShapeMismatch:
        raise ToolError("MCP config is not valid JSON.") from None
    if not isinstance(parsed, dict):
        raise ToolError("MCP config must be a JSON object.")
    return parsed


class _BadServer(Exception):
    def __init__(self, detail: SkipDetail) -> None:
        super().__init__(detail.value)
        self.detail = detail


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise _BadServer(SkipDetail.SERVER_MALFORMED)
    if len(value) > MAX_STRING:
        raise _BadServer(SkipDetail.SERVER_OVER_LIMIT)
    return value


def _optional_text(entry: Mapping[str, Any], key: str) -> str | None:
    return None if entry.get(key) is None else _text(entry[key])


def _env_value(value: object) -> str | None:
    """VS Code documents env values as strings, numbers, or null."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return _text(value)


def _object(entry: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = entry.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _BadServer(SkipDetail.SERVER_MALFORMED)
    return value


def normalize_server(index: int, name: str, entry: object) -> tuple[Server, int]:
    """A Server plus the number of unknown fields it had, or raise _BadServer."""
    if not isinstance(entry, dict):
        raise _BadServer(SkipDetail.SERVER_MALFORMED)
    _text(name)
    args = entry.get("args")
    if args is None:
        args = []
    if not isinstance(args, list):
        raise _BadServer(SkipDetail.SERVER_MALFORMED)
    if len(args) > MAX_ARGS:
        raise _BadServer(SkipDetail.SERVER_OVER_LIMIT)
    env = tuple((_text(k), _env_value(v)) for k, v in _object(entry, "env").items())
    headers = tuple((_text(k), _text(v)) for k, v in _object(entry, "headers").items())
    auth = tuple(
        (_text(k), _text(v))
        for k, v in _object(entry, "auth").items()
        if isinstance(v, str)  # scopes is a list
    )
    server = Server(
        index=index,
        name=name,
        type=_optional_text(entry, "type"),
        command=_optional_text(entry, "command"),
        args=tuple(_text(a) for a in args),
        env=env,
        headers=headers,
        url=_optional_text(entry, "url"),
        auth=auth,
        # Names of documented fields only, so no target text is kept.
        fields=frozenset(
            k for k in KNOWN_FIELDS if k in entry and entry[k] is not None
        ),
    )
    return server, sum(1 for k in entry if k not in KNOWN_FIELDS)


def _tables(config: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    for key in _TABLES:
        if key in config:
            table = config[key]
            if not isinstance(table, dict):
                raise ToolError(
                    f"{key} must be an object mapping server names to servers."
                )
            yield table
    projects = config.get(_PROJECTS)
    if isinstance(projects, dict):
        for project in projects.values():
            if isinstance(project, dict) and isinstance(
                project.get("mcpServers"), dict
            ):
                yield project["mcpServers"]


# --- running rules


def _exception_reason(exc: Exception) -> SkipReason:
    if isinstance(exc, OSError):  # rule data file missing or unreadable
        return SkipReason.NOT_DETERMINABLE
    if isinstance(exc, (RuleDataError, yaml.YAMLError)):
        return SkipReason.SHAPE_MISMATCH
    return SkipReason.RULE_ERROR


class _Run:
    def __init__(self) -> None:
        self.ran: list[str] = []
        self.skipped: list[SkippedCheck] = []
        self.findings: list[Finding] = []

    def skip(
        self, check: str, reason: SkipReason, detail: SkipDetail | None = None
    ) -> None:
        self.skipped.append(SkippedCheck(check, reason, detail))

    def run(self, check: str, rule: Callable[[], rules.RuleResult]) -> None:
        try:
            result = rule()
        # A crash is a skipped check, never a pass. Logged by type only (no exc_info):
        # a message or traceback could carry config text.
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s failed: %s", check, type(exc).__name__)
            self.skip(check, _exception_reason(exc))
            return
        if isinstance(result, rules.Skip):
            self.skip(check, result.reason, result.detail)
        else:
            self.ran.append(check)
            self.findings.extend(result)


def _rule(name: str) -> Callable[[Server], rules.RuleResult]:
    # Looked up on each call, so a test can replace a rule on the module.
    return getattr(rules, name)


def scan_mcp_config(config_text: object) -> Report:
    """Check an MCP client config's servers for unpinned runners, plain-http remotes,
    hardcoded secrets, shell wrappers, broad filesystem paths, non-registry package
    sources and risky env entries (docs/rules-config.md)."""
    config = parse_config(config_text)
    tables = list(_tables(config))
    if not tables:
        raise ToolError(
            "No server table found, so no checks ran. Expected mcpServers (Claude Code, "
            "Claude Desktop, Cursor) or servers (VS Code) at the top level."
        )
    run = _Run()
    index = scanned = skipped = unknown_fields = 0
    over_cap = False
    for table in tables:
        for name, entry in table.items():
            if index >= MAX_SERVERS:
                over_cap = True
                skipped += 1
                index += 1
                continue
            try:
                server, unknown = normalize_server(index, name, entry)
            except _BadServer as bad:
                for rule_id, _ in _RULES:
                    run.skip(
                        f"{rule_id}:servers[{index}]",
                        SkipReason.SHAPE_MISMATCH,
                        bad.detail,
                    )
                skipped += 1
                index += 1
                continue
            unknown_fields += unknown
            for rule_id, fn in _RULES:
                run.run(
                    f"{rule_id}:servers[{index}]",
                    lambda fn=fn, s=server: _rule(fn)(s),
                )
            scanned += 1
            index += 1
    if over_cap:
        for rule_id, _ in _RULES:
            run.skip(
                f"{rule_id}:servers[{MAX_SERVERS}:]",
                SkipReason.SHAPE_MISMATCH,
                SkipDetail.TOO_MANY_SERVERS,
            )
    if index == 0:
        for rule_id, _ in _RULES:
            run.skip(rule_id, SkipReason.NOT_APPLICABLE)

    unknown_top = sum(
        1
        for k in config
        if k not in _TABLES and k != _PROJECTS and k not in _OTHER_TOP_LEVEL
    )
    notes = [f"Servers scanned: {scanned}. Servers skipped: {skipped}."]
    if unknown_fields:
        notes.append(f"Unrecognized server fields ignored: {unknown_fields}.")
    if unknown_top:
        notes.append(f"Unrecognized top-level keys ignored: {unknown_top}.")
    return build_report(
        run.findings,
        Coverage(ran=tuple(run.ran), skipped=tuple(run.skipped)),
        notes=notes,
    )
