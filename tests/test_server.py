"""The FastMCP server, in-process through fastmcp.Client. No network: respx mocks every request
and fails on any unmocked one. Invented zqvex-* names only."""

import asyncio
import copy
import json
import sys
import time
from importlib.metadata import version as dist_version
from pathlib import Path

import fastmcp
import httpx
import pytest
import pytest_asyncio
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_supply_audit import package_audit, registry_audit, server, server_audit
from mcp_supply_audit.clients import _http
from mcp_supply_audit.findings import NOTE, SkipDetail, SkipReason
from mcp_supply_audit.validation import MAX_TOOLS_LIST_BYTES

TESTS = Path(__file__).resolve().parent
TOOL_NAMES = {
    "scan_tool_definitions",
    "audit_registry_entry",
    "check_typosquat",
    "audit_package",
    "scan_mcp_config",
    "audit_server",
}
# Only the tools that send requests are open-world; every tool is read-only.
OPEN_WORLD = {
    "scan_tool_definitions": False,
    "audit_registry_entry": True,
    "check_typosquat": False,
    "audit_package": True,
    "scan_mcp_config": False,
    "audit_server": True,
}
NAME = "io.github.zqvex/zqvex-mcp"
REGISTRY_RE = (
    r"^https://registry\.modelcontextprotocol\.io/v0/servers/[^/]+/versions/latest"
    r"\?include_deleted=true$"
)
PYPI = "https://pypi.org"
RELEASE_URL = f"{PYPI}/pypi/zqvex-pkg/1.2.0/json"
OSV_URL = "https://api.osv.dev/v1/query"
FILES = ("zqvex_pkg-1.2.0-py3-none-any.whl", "zqvex_pkg-1.2.0.tar.gz")
CONFIG = json.dumps(
    {"mcpServers": {"zqvex": {"command": "npx", "args": ["-y", "zqvex-mcp"]}}}
)


def load(path):
    return json.loads((TESTS / "fixtures" / path).read_text(encoding="utf-8"))


RELEASE = load("package/pypi_release_zqvex.json")
OSV_BODY = load("package/osv_query_zqvex.json")
PROV = load("package/pypi_provenance_zqvex.json")
BENIGN_TOOLS = load("tool_defs/benign/get_weather.json")
HIDDEN_TOOLS = load("tool_defs/suspicious/td001_hidden_characters.json")


def zqvex_entry(n_packages=1):
    """The real entry fixture's shape, renamed to invented zqvex-* names."""
    entry = copy.deepcopy(load("api/registry_server_version.json"))
    s = entry["server"]
    s["name"] = NAME
    s["description"] = "Invented server for tests."
    s["repository"]["url"] = "https://github.com/zqvex/zqvex-mcp"
    package = dict(s["packages"][0], identifier="zqvex-pkg", version="1.2.0")
    s["packages"] = [dict(package) for _ in range(n_packages)]
    return entry


def ok(body):
    return httpx.Response(200, json=body)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def fake_sleep(delay):
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)


@pytest.fixture
def router():
    with respx.mock(assert_all_called=False) as mock:
        yield mock


def mock_sources(router, *, entry=None, release=None, osv=None):
    router.get(url__regex=REGISTRY_RE).mock(
        return_value=entry
        if isinstance(entry, httpx.Response)
        else ok(entry or zqvex_entry())
    )
    router.get(RELEASE_URL).mock(return_value=release or ok(RELEASE))
    for filename in FILES:
        router.get(f"{PYPI}/integrity/zqvex-pkg/1.2.0/{filename}/provenance").mock(
            return_value=ok(PROV)
        )
    router.post(OSV_URL).mock(return_value=osv or ok(OSV_BODY))


@pytest_asyncio.fixture
async def client():
    async with Client(server.mcp) as c:
        yield c


async def call(client, tool, args):
    result = await client.call_tool(tool, args)
    return result.structured_content


def ran(report):
    return set(report["coverage"]["ran"])


def skipped(report):
    return {
        s["check"]: (s["reason"], s.get("detail"))
        for s in report["coverage"]["skipped"]
    }


# --- listing and schemas


BASE_ARGS = {
    "scan_tool_definitions": {"snapshot": '{"tools": []}'},
    "audit_registry_entry": {"name": NAME},
    "check_typosquat": {"name": "zqvex-pkg", "ecosystem": "pypi"},
    "audit_package": {"name": "zqvex-pkg", "ecosystem": "pypi", "version": "1.2.0"},
    "scan_mcp_config": {"config_text": CONFIG},
    "audit_server": {"name": "zqvex-pkg", "ecosystem": "pypi", "version": "1.2.0"},
}
# Each string argument of each tool, including optional ones.
STRING_ARGS = [(tool, arg) for tool, args in BASE_ARGS.items() for arg in args] + [
    ("audit_server", "tools_snapshot")
]
PATHS = (
    "/etc/passwd",
    "../../etc/passwd",
    "../zqvex",
    "~/.claude.json",
    "C:\\Users\\zqvex\\.ssh\\id_rsa",
    "file:///etc/passwd",
)


@pytest.mark.asyncio
async def test_lists_exactly_six_tools_with_use_when(client):
    tools = await client.list_tools()
    assert {t.name for t in tools} == TOOL_NAMES
    assert len(tools) == 6
    for tool in tools:
        assert tool.description and "Use when" in tool.description, tool.name
        assert "Prefer another tool when" in tool.description, tool.name
        assert "not proof" in tool.description, tool.name


@pytest.mark.asyncio
async def test_annotations_a_client_sees(client):
    tools = {t.name: t.annotations for t in await client.list_tools()}
    assert set(tools) == set(OPEN_WORLD)
    for name, open_world in OPEN_WORLD.items():
        assert tools[name].read_only_hint is True, name
        assert tools[name].open_world_hint is open_world, name


@pytest.mark.asyncio
async def test_docstrings_state_caller_limits(client):
    tools = {t.name: t.description for t in await client.list_tools()}
    assert "large PyPI projects need an explicit version" in tools["audit_package"]
    assert "no install-script check for\nPyPI" in tools["audit_package"]
    assert "no publish time" in tools["audit_package"]
    assert "case-sensitive" in tools["audit_registry_entry"]
    assert "copy the name exactly" in tools["audit_registry_entry"]
    typosquat = tools["check_typosquat"]
    assert "dated 2026-11-03" in typosquat and "generated_at" in typosquat
    assert "curated names" in typosquat and "only" in typosquat


@pytest.mark.asyncio
async def test_every_string_argument_has_a_size_cap(client):
    for tool in await client.list_tools():
        for name, prop in tool.input_schema["properties"].items():
            arms = prop.get("anyOf", [prop])
            for arm in arms:
                if arm.get("type") == "string":
                    assert "maxLength" in arm or "enum" in arm, (tool.name, name)


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool", "arg"), STRING_ARGS)
@pytest.mark.parametrize("path", PATHS)
async def test_every_argument_rejects_a_path(client, router, tool, arg, path):
    with pytest.raises(ToolError) as raised:
        await client.call_tool(tool, {**BASE_ARGS[tool], arg: path})
    message = str(raised.value)
    assert path not in message
    assert len(message) < 300
    assert not router.calls  # rejected before any request


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PATHS)
async def test_registry_name_rejects_a_path(client, router, path):
    for tool, args in (
        ("audit_server", {"name": path}),
        ("audit_registry_entry", {"name": path}),
        ("check_typosquat", {"name": path, "ecosystem": "registry"}),
    ):
        with pytest.raises(ToolError) as raised:
            await client.call_tool(tool, args)
        assert path not in str(raised.value)
    assert not router.calls


@pytest.mark.asyncio
async def test_a_real_file_path_is_never_read(client, tmp_path):
    # A valid config on disk: passing its path must not scan the file.
    config = tmp_path / "zqvex.json"
    config.write_text(CONFIG, encoding="utf-8")
    snapshot = tmp_path / "tools.json"
    snapshot.write_text(json.dumps(BENIGN_TOOLS), encoding="utf-8")
    with pytest.raises(ToolError, match="not valid JSON"):
        await client.call_tool("scan_mcp_config", {"config_text": str(config)})
    with pytest.raises(ToolError, match="not valid JSON"):
        await client.call_tool("scan_tool_definitions", {"snapshot": str(snapshot)})


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool", "arg"), STRING_ARGS)
async def test_every_argument_rejects_oversized_input(client, router, tool, arg):
    schema = {t.name: t.input_schema for t in await client.list_tools()}[tool]
    prop = schema["properties"][arg]
    caps = [a["maxLength"] for a in prop.get("anyOf", [prop]) if "maxLength" in a]
    value = "a" * ((caps[0] if caps else 10_000) + 1)
    with pytest.raises(ToolError) as raised:
        await client.call_tool(tool, {**BASE_ARGS[tool], arg: value})
    assert str(raised.value) == server._INVALID_ARGUMENTS
    assert not router.calls


@pytest.mark.asyncio
async def test_scan_tool_definitions_snapshot_object_is_a_fixed_error(client):
    big = {"tools": [{"name": "zqvex", "description": "a" * (1024 * 1024)}]}
    for snapshot in (BENIGN_TOOLS, BENIGN_TOOLS["tools"], big):
        with pytest.raises(ToolError) as raised:
            await client.call_tool("scan_tool_definitions", {"snapshot": snapshot})
        assert str(raised.value) == server._INVALID_ARGUMENTS


@pytest.mark.asyncio
async def test_scan_tool_definitions_size_cap_before_parsing(client, monkeypatch):
    def never(data):
        raise AssertionError("parsed before the size cap")

    monkeypatch.setattr(server_audit, "safe_json", never)
    wide = "é" * (MAX_TOOLS_LIST_BYTES // 2 + 1)  # under the char cap, over in bytes
    with pytest.raises(ToolError, match="too large"):
        await client.call_tool("scan_tool_definitions", {"snapshot": wide})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"tools": [NaN]}', "tools/list snapshot is not valid JSON."),
        ("{tools", "tools/list snapshot is not valid JSON."),
        (
            "[" * 65 + "]" * 65,
            "tools/list snapshot is nested too deeply (max depth 64).",
        ),
        ("1", "tools/list snapshot must be a JSON object or array."),
    ],
)
async def test_scan_tool_definitions_parsed_with_safe_json(client, text, message):
    with pytest.raises(ToolError) as raised:
        await client.call_tool("scan_tool_definitions", {"snapshot": text})
    assert str(raised.value) == message


@pytest.mark.asyncio
async def test_scan_tool_definitions_compact_text_near_the_cap_is_scanned(client):
    # Compact text just under 1 MiB: re-encoding the parsed object with json.dumps'
    # default ", " separators would exceed the cap, so it must not be re-encoded.
    tool = {"name": "zqvex", "description": "a"}
    per_tool = len(json.dumps(tool, separators=(",", ":"))) + 1  # with its comma
    count = (MAX_TOOLS_LIST_BYTES - len('{"tools":[]}')) // per_tool
    text = json.dumps({"tools": [tool] * count}, separators=(",", ":"))
    assert len(text) <= MAX_TOOLS_LIST_BYTES < len(json.dumps(json.loads(text)))
    report = await call(client, "scan_tool_definitions", {"snapshot": text})
    assert "TD001" in ran(report)


@pytest.mark.asyncio
async def test_audit_server_snapshot_object_is_a_fixed_error(client, router):
    with pytest.raises(ToolError) as raised:
        await client.call_tool(
            "audit_server",
            {"name": "zqvex-pkg", "ecosystem": "pypi", "tools_snapshot": BENIGN_TOOLS},
        )
    assert str(raised.value) == server._INVALID_ARGUMENTS
    assert not router.calls
    # Called directly (no schema in front), the module rejects it with its own fixed text.
    with pytest.raises(ToolError) as raised:
        await server_audit.audit_server(NAME, tools_snapshot=BENIGN_TOOLS)
    assert str(raised.value) == "tools_snapshot must be JSON text, not an object."


@pytest.mark.asyncio
async def test_audit_server_snapshot_size_cap_before_parsing(monkeypatch):
    def never(data):
        raise AssertionError("parsed before the size cap")

    monkeypatch.setattr(server_audit, "safe_json", never)
    big = "[" + " " * MAX_TOOLS_LIST_BYTES + "]"
    with pytest.raises(ToolError, match="too large"):
        await server_audit.audit_server(NAME, tools_snapshot=big)
    wide = "é" * (MAX_TOOLS_LIST_BYTES // 2 + 1)  # under the char cap, over in bytes
    with pytest.raises(ToolError, match="too large"):
        await server_audit.audit_server(NAME, tools_snapshot=wide)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text", ['{"tools": [NaN]}', "{tools", '{"tools": [1}', "[" * 65 + "]" * 65]
)
async def test_audit_server_snapshot_parsed_with_safe_json(router, text):
    with pytest.raises(ToolError) as raised:
        await server_audit.audit_server(NAME, tools_snapshot=text)
    assert str(raised.value) in (
        "tools/list snapshot is not valid JSON.",
        "tools/list snapshot is nested too deeply (max depth 64).",
    )
    assert not router.calls


# --- invalid input


SECRET = "zqvex-SECRET-marker"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("scan_tool_definitions", {"snapshot": f"{{{SECRET}"}),
        ("scan_tool_definitions", {"snapshot": json.dumps({SECRET: 1})}),
        ("audit_registry_entry", {"name": f"{SECRET} x"}),
        ("check_typosquat", {"name": f"{SECRET}!", "ecosystem": "npm"}),
        ("check_typosquat", {"name": "zqvex-pkg", "ecosystem": SECRET}),
        (
            "audit_package",
            {"name": "zqvex-pkg", "ecosystem": "pypi", "version": f"{SECRET} 1"},
        ),
        ("audit_package", {"name": f"@{SECRET}", "ecosystem": "pypi"}),
        ("scan_mcp_config", {"config_text": f"[{SECRET}]"}),
        ("scan_mcp_config", {"config_text": json.dumps({"other": SECRET})}),
        ("audit_server", {"name": f"{SECRET}!"}),
        ("audit_server", {"name": "zqvex-pkg"}),  # package name without ecosystem
        ("audit_server", {"name": NAME, "ecosystem": "pypi"}),
        ("audit_server", {"name": NAME, "version": "1.2.0"}),
        ("audit_server", {"name": NAME, "extra": SECRET}),
        (
            "audit_server",
            {"name": "zqvex-pkg", "ecosystem": "npm", "tools_snapshot": {SECRET: []}},
        ),
    ],
)
async def test_invalid_input_is_a_short_tool_error_without_echo(
    client, router, tool, args
):
    with pytest.raises(ToolError) as raised:
        await client.call_tool(tool, args)
    message = str(raised.value)
    assert SECRET not in message
    assert "Traceback" not in message
    assert 0 < len(message) < 300
    assert not router.calls


# --- happy paths


@pytest.mark.asyncio
async def test_scan_tool_definitions(client):
    clean = await call(
        client, "scan_tool_definitions", {"snapshot": json.dumps(BENIGN_TOOLS)}
    )
    assert clean["assessment"] == "no_findings_detected"
    assert clean["note"] == NOTE
    hidden = await call(
        client, "scan_tool_definitions", {"snapshot": json.dumps(HIDDEN_TOOLS)}
    )
    assert "TD001" in {f["rule_id"] for f in hidden["findings"]}
    assert all("untrusted_text" in f["evidence"] for f in hidden["findings"])


@pytest.mark.asyncio
async def test_audit_registry_entry(client, router):
    mock_sources(router)
    report = await call(client, "audit_registry_entry", {"name": NAME})
    assert {"RG002", "RG006", "RG001:packages[0]"} <= ran(report)
    assert report["note"] == NOTE


@pytest.mark.asyncio
async def test_check_typosquat(client, router):
    report = await call(
        client, "check_typosquat", {"name": "zqvex-pkg", "ecosystem": "pypi"}
    )
    assert report["data_sources"][0]["name"] == "data/reference_names.json"
    assert "TS001" in ran(report)
    assert not router.calls  # local reference list only


@pytest.mark.asyncio
async def test_audit_package(client, router):
    mock_sources(router)
    report = await call(client, "audit_package", BASE_ARGS["audit_package"])
    assert report["audited"] == {
        "ecosystem": "pypi",
        "name": "zqvex-pkg",
        "version": "1.2.0",
    }
    assert "PK001" in ran(report)
    assert skipped(report)["PK003"][0] == "not_determinable"


@pytest.mark.asyncio
async def test_scan_mcp_config(client, router):
    report = await call(client, "scan_mcp_config", {"config_text": CONFIG})
    assert "CF001:servers[0]" in ran(report)
    assert "CF001" in {f["rule_id"] for f in report["findings"]}
    assert not router.calls


@pytest.mark.asyncio
async def test_audit_server_registry_name(client, router):
    mock_sources(router)
    report = await call(
        client,
        "audit_server",
        {"name": NAME, "tools_snapshot": json.dumps(BENIGN_TOOLS)},
    )
    assert {
        "audit_registry_entry/RG002",
        "audit_package:packages[0]/PK001",
        "check_typosquat:name/TS001",
        "check_typosquat:packages[0]/TS001",
        "scan_tool_definitions/TD001",
    } <= ran(report)
    assert report["audited_by_report"] == {
        "audit_package:packages[0]": {
            "ecosystem": "pypi",
            "name": "zqvex-pkg",
            "version": "1.2.0",
        }
    }
    assert all("/" in f["location"] for f in report["findings"])
    assert json.dumps(report).count(NOTE) == 1


@pytest.mark.asyncio
async def test_audit_server_package_name_skips_registry_checks(client, router):
    mock_sources(router)
    report = await call(client, "audit_server", BASE_ARGS["audit_server"])
    assert {"audit_package/PK001", "check_typosquat/TS001"} <= ran(report)
    registry = {
        k: v
        for k, v in skipped(report).items()
        if k.startswith("audit_registry_entry/")
    }
    assert set(registry) == {f"audit_registry_entry/RG{n:03d}" for n in range(1, 12)}
    assert set(registry.values()) == {
        ("not_determinable", "registry entry not provided")
    }
    assert not any(
        "registry.modelcontextprotocol.io" in str(c.request.url) for c in router.calls
    )


@pytest.mark.asyncio
async def test_audit_server_caps_packages_at_three(client, router):
    mock_sources(router, entry=zqvex_entry(n_packages=5))
    report = await call(client, "audit_server", {"name": NAME})
    assert len(report["audited_by_report"]) == 3
    limit = ("not_determinable", "more packages than audit_server checks")
    for i in (3, 4):
        assert skipped(report)[f"audit_package:packages[{i}]"] == limit
        assert skipped(report)[f"check_typosquat:packages[{i}]"] == limit


@pytest.mark.asyncio
async def test_audit_server_missing_entry_is_a_partial_report(client, router):
    not_found = httpx.Response(404, json=load("api/registry_server_not_found.json"))
    mock_sources(router, entry=not_found)
    report = await call(client, "audit_server", {"name": NAME})
    missing = ("not_determinable", "registry entry not found")
    assert skipped(report)["audit_registry_entry"] == missing
    assert skipped(report)["audit_package"] == missing
    assert "check_typosquat:name/TS001" in ran(report)


# --- partial results


@pytest.mark.asyncio
async def test_audit_server_names_a_failing_sub_check(client, router):
    # PyPI and OSV both down: audit_package cannot run at all; the rest still reports.
    mock_sources(router, release=httpx.Response(503), osv=httpx.Response(503))
    report = await call(client, "audit_server", {"name": NAME})
    assert skipped(report)["audit_package:packages[0]"] == ("source_unreachable", None)
    assert "audit_registry_entry/RG002" in ran(report)
    assert "check_typosquat:packages[0]/TS001" in ran(report)
    texts = {s["check"]: s["text"] for s in report["coverage"]["skipped"]}
    assert "could not be reached" in texts["audit_package:packages[0]"]


@pytest.mark.asyncio
async def test_audit_server_latest_unresolved_is_a_skip_with_reason(client, router):
    too_large = httpx.Response(
        200, content=b"{}", headers={"Content-Length": str(10**9)}
    )
    router.get(f"{PYPI}/pypi/zqvex-pkg/json").mock(return_value=too_large)
    report = await call(
        client, "audit_server", {"name": "zqvex-pkg", "ecosystem": "pypi"}
    )
    assert skipped(report)["audit_package"] == (
        "response_too_large",
        "latest version could not be resolved",
    )
    assert "check_typosquat/TS001" in ran(report)


@pytest.mark.asyncio
async def test_audit_server_deadline_returns_partial_report(client, monkeypatch):
    async def slow(*args, **kwargs):
        await asyncio.sleep(30)

    monkeypatch.setattr(server_audit, "DEADLINE_SECONDS", 0.2)
    monkeypatch.setattr(package_audit, "audit_package", slow)
    started = time.monotonic()
    report = await call(client, "audit_server", BASE_ARGS["audit_server"])
    assert time.monotonic() - started < 5
    assert skipped(report)["audit_package"] == (
        SkipReason.SOURCE_UNREACHABLE.value,
        SkipDetail.DEADLINE.value,
    )
    assert "check_typosquat/TS001" in ran(report)


@pytest.mark.asyncio
async def test_audit_server_deadline_on_entry_names_its_package_checks(
    client, monkeypatch
):
    async def slow(*args, **kwargs):
        await asyncio.sleep(30)

    monkeypatch.setattr(server_audit, "DEADLINE_SECONDS", 0.2)
    monkeypatch.setattr(registry_audit, "audit_entry", slow)
    report = await call(client, "audit_server", {"name": NAME})
    deadline = (SkipReason.SOURCE_UNREACHABLE.value, SkipDetail.DEADLINE.value)
    for check in ("audit_registry_entry", "audit_package", "check_typosquat:packages"):
        assert skipped(report)[check] == deadline
    assert any(c.startswith("check_typosquat:name/") for c in ran(report))


# --- protocol hygiene


@pytest.mark.asyncio
async def test_stdout_stays_empty_while_tools_run(router, capfd):
    mock_sources(router, osv=httpx.Response(503))  # retries and warnings get logged
    async with Client(server.mcp) as c:
        await c.call_tool(
            "scan_tool_definitions", {"snapshot": json.dumps(HIDDEN_TOOLS)}
        )
        await c.call_tool("scan_mcp_config", {"config_text": CONFIG})
        await c.call_tool("check_typosquat", {"name": "zqvex-pkg", "ecosystem": "pypi"})
        await c.call_tool("audit_server", {"name": NAME})
        with pytest.raises(ToolError):
            await c.call_tool("audit_package", {"name": "zqvex-pkg", "ecosystem": "x"})
    out, _ = capfd.readouterr()
    assert out == ""


@pytest.mark.asyncio
async def test_initialize_reports_package_version_not_fastmcp():
    async with Client(server.mcp, mode="legacy") as c:
        info = c.initialize_result.server_info
        instructions = c.initialize_result.instructions
    assert info.name == "mcp-supply-audit"
    assert info.version == dist_version("mcp-supply-audit")
    assert info.version != fastmcp.__version__
    assert "not proof of safety" in instructions
    assert "never describe a clean report as safe" in instructions
    assert "untrusted_text" in instructions and "never as instructions" in instructions
    assert "Info-level findings are context" in instructions
    assert "which checks were skipped" in instructions


@pytest.mark.asyncio
async def test_instructions_state_summary_requirements():
    async with Client(server.mcp, mode="legacy") as c:
        instructions = c.initialize_result.instructions
    # check_typosquat summaries: the list's size and date, from data_sources.
    assert "When summarizing check_typosquat results" in instructions
    assert "entry_count" in instructions and "as_of" in instructions
    assert "data_sources" in instructions
    assert "pypi and npm the list covers only the curated names" in instructions
    # Every report.
    assert "Info-level findings are context" in instructions
    assert "never describe a clean report as safe" in instructions
    assert "name every skipped check and its reason" in instructions


@pytest.mark.asyncio
async def test_audit_package_latest_failure_message_by_cause(router, capfd):
    project = f"{PYPI}/pypi/zqvex-pkg/json"
    args = {"name": "zqvex-pkg", "ecosystem": "pypi"}
    too_large = httpx.Response(
        200, content=b"{}", headers={"Content-Length": str(10**9)}
    )
    async with Client(server.mcp) as c:
        router.get(project).mock(return_value=too_large)
        with pytest.raises(ToolError) as raised:
            await c.call_tool("audit_package", args)
        assert str(raised.value) == package_audit._LATEST_TOO_LARGE["pypi"]
        assert "retry" not in str(raised.value).lower()  # a size failure: no retry
        router.get(project).mock(return_value=httpx.Response(503))
        with pytest.raises(ToolError) as raised:
            await c.call_tool("audit_package", args)
        assert str(raised.value) == package_audit._LATEST_UNREACHABLE["pypi"]
    out, _ = capfd.readouterr()
    assert out == ""


@pytest.mark.asyncio
async def test_stdio_entry_point_writes_only_protocol_to_stdout():
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "from mcp_supply_audit.server import main; main()",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "zqvex-test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    try:
        for m in messages:
            proc.stdin.write((json.dumps(m) + "\n").encode())
        await proc.stdin.drain()
        replies = [
            json.loads(await asyncio.wait_for(proc.stdout.readline(), 20))
            for _ in range(2)
        ]
        proc.stdin.close()
        rest = await asyncio.wait_for(proc.stdout.read(), 20)
    finally:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
    assert replies[0]["result"]["serverInfo"]["version"] == dist_version(
        "mcp-supply-audit"
    )
    tools = replies[1]["result"]["tools"]
    assert len(tools) == 6
    # The annotations exactly as a client receives them on the wire.
    assert {t["name"]: t["annotations"] for t in tools} == {
        name: {"readOnlyHint": True, "openWorldHint": open_world}
        for name, open_world in OPEN_WORLD.items()
    }
    assert rest == b""  # nothing else on stdout
