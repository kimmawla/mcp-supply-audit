"""RG005 matches the registry verifier; RG009-RG011 evidence never holds a secret; the OWASP
table in docs/rules-registry.md matches the code and owasp.py. No network calls."""

import ast
import copy
import dataclasses
import json
import re
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients import _http
from mcp_supply_audit.clients._http import HttpClient
from mcp_supply_audit.detectors import registry_rules
from mcp_supply_audit.detectors.registry_rules import (
    RG005_TITLE_PREFIX,
    RULE_OWASP,
    has_pypi_marker,
    redact_url,
    rg005_mcpb_static,
    rg005_ownership_marker,
)
from mcp_supply_audit.findings import build_report
from mcp_supply_audit.owasp import OWASP_MCP_TOP_10
from mcp_supply_audit.registry_audit import audit_registry_entry, run_registry_rules

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "tests/fixtures/api"
NAME = "io.github.kimmawla/vuln-triage-mcp"
ZWSP, RLO, BS = chr(0x200B), chr(0x202E), chr(92)
REGISTRY_RE = (
    r"^https://registry\.modelcontextprotocol\.io/v0/servers/[^/]+/versions/latest"
    r"\?include_deleted=true$"
)


def load(name):
    return json.loads((API / name).read_text(encoding="ascii"))


ENTRY = load("registry_server_version.json")


def remote_entry(*urls, name=NAME):
    """Normalized entry (clients/registry.py shape): remote-only, given URLs."""
    return {
        "name": name,
        "version": "0.1.0",
        "repository_url": "https://github.com/kimmawla/vuln-triage-mcp",
        "packages": [],
        "remotes": [
            {"type": "streamable-http", "url": u, "variables": ()} for u in urls
        ],
        "status": "active",
        "status_message": None,
        "meta_shape": "nested",
    }


def report_for(entry):
    findings, coverage = run_registry_rules(entry, [])
    return build_report(findings, coverage)


# --- secret-safe evidence


PASSWORD = "Pa55w0rd-SECRET-a1"
TOKEN = "tok-SECRET-b2"
HIDDEN_SECRET = "hid" + ZWSP + "den-SECRET-c3" + RLO
HOSTILE_URL = (
    f"http://admin:{PASSWORD}@mcp.example.com:8443/mcp"
    f"?page=2&token={TOKEN}&to{ZWSP}ken={HIDDEN_SECRET}&a%70i_key={TOKEN}x#frag-SECRET-d4"
)
SECRETS = (
    PASSWORD,
    TOKEN,
    HIDDEN_SECRET,
    "hid",
    "den-SECRET-c3",
    "frag-SECRET-d4",
    "admin",
)


def test_secrets_appear_nowhere():
    report = report_for(remote_entry(HOSTILE_URL))
    rules = {f.rule_id for f in report.findings}
    assert {"RG009", "RG011"} <= rules
    rg011 = sorted(f.title for f in report.findings if f.rule_id == "RG011")
    # userinfo; one finding for the three credential parameters; the port.
    assert rg011 == [
        "Remote URL embeds a credential parameter",
        "Remote URL embeds credentials (userinfo)",
        "Remote URL uses an unusual port",
    ]
    surfaces = [
        json.dumps(report.to_dict(), ensure_ascii=False),
        json.dumps(report.to_dict()),
        repr(report),
        str(report),
        *(repr(f) for f in report.findings),
        *(str(f) for f in report.findings),
        *(f.evidence for f in report.findings),
        *(f.title + f.location for f in report.findings),
    ]
    for surface in surfaces:
        for secret in SECRETS:
            assert secret not in surface, (secret, surface[:200])


def test_remote_evidence_is_origin_and_parameter_names_only():
    report = report_for(remote_entry(HOSTILE_URL))
    by_title = {f.title: f.evidence for f in report.findings}
    origin = "http://mcp.example.com:8443"
    assert by_title["Remote URL does not use https"] == origin
    assert by_title["Remote URL embeds credentials (userinfo)"] == origin
    assert by_title["Remote URL uses an unusual port"] == origin
    params = by_title["Remote URL embeds a credential parameter"]
    assert params == f"{origin} [parameters: token, to{ZWSP}ken, a%70i_key]"
    for evidence in by_title.values():
        assert ":8443/" not in evidence  # no path
        assert "page=" not in evidence and "#" not in evidence
        assert "<redacted>" not in evidence  # nothing to redact: values are never shown


def test_userinfo_with_slash_in_password_is_redacted():
    redacted, hits = redact_url(
        "https://u:pa/ss-SECRET@h.example/mcp", frozenset({"token"})
    )
    assert redacted == "https://<redacted>@h.example/mcp"
    assert [h.kind for h in hits] == ["userinfo"]


def test_placeholder_credential_is_low_and_redacted():
    report = report_for(remote_entry("https://mcp.example.com/mcp?api_key={api_key}"))
    (finding,) = report.findings
    assert finding.severity.value == "low"
    assert finding.evidence == "https://mcp.example.com [parameters: api_key]"


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/mcp",
        "https://mcp.example.com/mcp?page=2&per_page=50&limit=10&offset=20",
        "https://mcp.example.com/mcp?cursor=abc&page_token=xyz&next_token=n&continuation=c",
        "https://mcp.example.com/mcp?cache=no&cache_key=k&nocache=1&v=3&ts=1700000000",
        "https://mcp.example.com/mcp?session_id=s1&sessionId=s2&session=s3&sid=4",
        "https://mcp.example.com/mcp?key=sort&auth=none&ref=main&format=json&lang=en",
        "https://mcp.example.com:443/mcp?tokenizer=bpe&max_tokens=100",
        "https://{tenant}.example.com/mcp?region={region}",
    ],
)
def test_benign_urls_have_no_rg009_or_rg011_finding(url):
    report = report_for(remote_entry(url))
    assert [f.rule_id for f in report.findings] == []


# --- static: RG009-RG011 can only pass the minimal-evidence builder's output

GUARDED = ("rg009_https", "rg010_host_in_namespace", "rg011_credentials", "rg011_port")
EVIDENCE_POSITION = (
    6  # _finding(rule_id, title, severity, confidence, owasp, location, evidence, ...)
)
FORBIDDEN_CALLS = {"evidence_snippet", "redact_url", "display_url", "Finding"}
# What url_evidence may read from the split URL.
ALLOWED_PARTS = {"scheme", "host", "port"}


def _name(node: ast.AST | None) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _call_name(call: ast.Call) -> str | None:
    return getattr(call.func, "id", None) or getattr(call.func, "attr", None)


def _is_parameter_names(node: ast.AST) -> bool:
    """Lists of collected parameter names: `literal`, `placeholder`, or `[key]`."""
    if _name(node) in {"literal", "placeholder"}:
        return True
    return isinstance(node, ast.List) and all(_name(e) == "key" for e in node.elts)


def unsafe_url_evidence(source: str) -> list[str]:
    problems = []
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    for name in GUARDED:
        fn = functions.get(name)
        if fn is None:
            continue
        for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
            called = _call_name(call)
            if called in FORBIDDEN_CALLS:
                problems.append(f"{name}: calls {called}")
            if called == "_finding":
                evidence = next(
                    (k.value for k in call.keywords if k.arg == "evidence"), None
                )
                if evidence is None and len(call.args) > EVIDENCE_POSITION:
                    evidence = call.args[EVIDENCE_POSITION]
                if not (
                    isinstance(evidence, ast.Call)
                    and _call_name(evidence) == "url_evidence"
                ):
                    problems.append(f"{name}: evidence is not url_evidence(...)")
            if called == "url_evidence":
                if call.keywords or _name(call.args[0] if call.args else None) != "url":
                    problems.append(f"{name}: url_evidence must take url")
                if len(call.args) > 1 and _name(call.args[1]) != "params":
                    problems.append(
                        f"{name}: url_evidence params must be the params name list"
                    )
            if called == "add":  # rg011_credentials' helper: the 4th argument is params
                params = call.args[3] if len(call.args) > 3 else None
                if params is not None and not _is_parameter_names(params):
                    problems.append(f"{name}: params must be parameter names")
            collects_names = called == "append" and _appends_to_name_lists(call)
            if collects_names and not (
                len(call.args) == 1 and _name(call.args[0]) == "key"
            ):
                problems.append(f"{name}: only parameter names may be collected")
    builder = functions.get("url_evidence")
    if builder is not None:
        for node in ast.walk(builder):
            if (
                isinstance(node, ast.Attribute)
                and _name(node.value) == "parts"
                and node.attr not in ALLOWED_PARTS
            ):
                problems.append(f"url_evidence: reads parts.{node.attr}")
        if not _url_only_split(builder):
            problems.append("url_evidence: uses url other than through _split_url(url)")
    return problems


def _appends_to_name_lists(call: ast.Call) -> bool:
    """`literal.append(...)`, `placeholder.append(...)`, or `(a if c else b).append(...)`."""
    target = getattr(call.func, "value", None)
    if isinstance(target, ast.IfExp):
        return {_name(target.body), _name(target.orelse)} & {
            "literal",
            "placeholder",
        } != set()
    return _name(target) in {"literal", "placeholder"}


def _url_only_split(builder: ast.FunctionDef) -> bool:
    """`url` appears in url_evidence only as the argument of _split_url(url)."""
    uses = [n for n in ast.walk(builder) if isinstance(n, ast.Name) and n.id == "url"]
    split_args = [
        c.args[0]
        for c in ast.walk(builder)
        if isinstance(c, ast.Call) and _call_name(c) == "_split_url" and c.args
    ]
    return len(uses) == len(split_args) and all(_name(a) == "url" for a in split_args)


def test_remote_rules_only_pass_url_evidence():
    source = Path(registry_rules.__file__).read_text(encoding="utf-8")
    assert unsafe_url_evidence(source) == []
    defined = {n.name for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
    assert set(GUARDED) | {"url_evidence"} <= defined


@pytest.mark.parametrize(
    "snippet",
    [
        "def rg009_https(entry, index):\n    return [_finding('RG009', 't', s, c, o, l, url, r)]",
        "def rg011_port(entry, index):\n    return [_finding('RG011', 't', s, c, o, l, evidence=url)]",
        "def rg011_credentials(entry, index):\n    return evidence_snippet(url, 0)",
        "def rg010_host_in_namespace(entry, index):\n    e = redact_url(url, n)[0]\n    return [_finding('RG010', 't', s, c, o, l, e, r)]",
        "def rg011_credentials(entry, index):\n    return [_finding('RG011', 't', s, c, o, l, display_url(url), r)]",
        "def rg011_credentials(entry, index):\n    return [_finding('RG011', 't', s, c, o, l, url_evidence(url, [value]), r)]",
        "def rg011_credentials(entry, index):\n    return [_finding('RG011', 't', s, c, o, l, url_evidence(raw_url), r)]",
        "def rg011_credentials(entry, index):\n    add('t', s, c, [value])",
        "def rg011_credentials(entry, index):\n    literal.append(value)",
        "def rg009_https(entry, index):\n    return [Finding(evidence=url)]",
        "def url_evidence(url, params=()):\n    parts = _split_url(url)\n    return parts.userinfo",
        "def url_evidence(url, params=()):\n    parts = _split_url(url)\n    return url",
    ],
)
def test_static_check_catches_other_evidence(snippet):
    assert unsafe_url_evidence(snippet)


# --- secrets in each part of a remote URL never surface

PATH_SECRET = "PathSecret" + "-p7Q2x"
PARAM_SECRET = "ParamSecret" + "-k9W4z"
USER_SECRET = "UserSecret" + "-u3E8r"
PASS_SECRET = "PassSecret" + "-w6T1y"
FRAG_SECRET = "FragSecret" + "-f5R0t"
AFTER_AT_SECRET = "AfterAt" + "-a2M9n"
SHAPED = "gh" + "p_" + "Z9y8" * 9  # GitHub-format value, built so no file holds it

PLACEMENTS = {
    "path segment": f"http://mcp.example.com:8443/tenant/{PATH_SECRET}/mcp",
    "shaped path segment": f"http://mcp.example.com:8443/v1/{SHAPED}/mcp",
    "unlisted parameter": f"http://mcp.example.com:8443/mcp?state={PARAM_SECRET}&page=2",
    "shaped unlisted parameter": f"http://mcp.example.com:8443/mcp?workspace={SHAPED}",
    "userinfo": f"http://{USER_SECRET}:{PASS_SECRET}@mcp.example.com:8443/mcp",
    "fragment": f"http://mcp.example.com:8443/mcp#{FRAG_SECRET}",
    "after an @ in the path": f"http://mcp.example.com:8443/mcp/a@{AFTER_AT_SECRET}",
    "all at once": (
        f"http://{USER_SECRET}:{PASS_SECRET}@mcp.example.com:8443/tenant/{PATH_SECRET}/{SHAPED}"
        f"?state={PARAM_SECRET}&workspace={SHAPED}&token={SHAPED}#{FRAG_SECRET}"
    ),
}
ALL_SECRETS = (
    PATH_SECRET,
    PARAM_SECRET,
    USER_SECRET,
    PASS_SECRET,
    FRAG_SECRET,
    AFTER_AT_SECRET,
    SHAPED,
)


def surfaces(report) -> list[str]:
    out = [
        json.dumps(report.to_dict(), ensure_ascii=False),
        json.dumps(report.to_dict()),
        repr(report),
        str(report),
    ]
    for finding in report.findings:
        out += [
            repr(finding),
            str(finding),
            json.dumps(finding.to_dict(), ensure_ascii=False),
        ]
        out += [str(getattr(finding, f.name)) for f in dataclasses.fields(finding)]
    return out


@pytest.mark.parametrize("placement", list(PLACEMENTS))
def test_secret_never_surfaces(placement):
    # A domain namespace whose domain the host is outside of, so RG009, RG010 and RG011
    # all produce findings for every placement.
    report = report_for(remote_entry(PLACEMENTS[placement], name="com.vendor/server"))
    rules = {f.rule_id for f in report.findings}
    assert "RG009" in rules
    assert "RG011" in rules
    for text in surfaces(report):
        for secret in ALL_SECRETS:
            assert secret not in text, (placement, secret)


@pytest.mark.parametrize(
    ("placement", "expected_titles"),
    [
        ("userinfo", {"Remote URL embeds credentials (userinfo)"}),
        (
            "shaped path segment",
            {"Remote URL path segment 1 matches the documented GitHub token format"},
        ),
        (
            "shaped unlisted parameter",
            {"Remote URL query value matches the documented GitHub token format"},
        ),
    ],
)
def test_secret_placements_are_flagged(placement, expected_titles):
    report = report_for(remote_entry(PLACEMENTS[placement], name="com.vendor/server"))
    titles = {f.title for f in report.findings if f.rule_id == "RG011"}
    assert expected_titles <= titles


def test_remote_evidence_holds_only_scheme_host_port_and_names():
    report = report_for(
        remote_entry(PLACEMENTS["all at once"], name="com.vendor/server")
    )
    allowed = {
        "http://mcp.example.com:8443",
        "http://mcp.example.com:8443 [parameters: token]",
        "http://mcp.example.com:8443 [parameters: workspace]",
    }
    assert {f.evidence for f in report.findings} <= allowed
    assert {f.rule_id for f in report.findings} == {"RG009", "RG010", "RG011"}


@pytest.mark.parametrize(
    ("url", "evidence"),
    [
        ("https://u:pw@h.example:8443/a/b?c=d#e", "https://h.example:8443"),
        ("https://h.example:NotAPort/a", "https://h.example:(invalid port)"),
        ("token=Secret&x://h.example/a", "(no scheme)"),
        ("https://h.example/a@b", "https://(ambiguous host)"),
        ("https://u:pa/ss@h.example/x", "https://(ambiguous host)"),
        ("https://h.example/p?x=a@b#c@d", "https://h.example"),
        ("https://{host}:{port}/mcp", "https://{host}:{port}"),
        ("https://[::1]:8443/x", "https://[::1]:8443"),
        ("mailto:someone@example.com", "(no scheme)"),
    ],
)
def test_url_evidence_slots(url, evidence):
    assert registry_rules.url_evidence(url) == evidence


def test_ambiguous_host_is_not_checked_against_namespace():
    report = report_for(
        remote_entry("https://mcp.vendor.com/a@other.example", name="com.vendor/server")
    )
    skipped = {s.check: s.reason.value for s in report.coverage.skipped}
    assert skipped["RG010:remotes[0]"] == "not_applicable"


# --- RG005 matches the verifier (mcpname.go, npm.go, mcpb.go)


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        (f"mcp-name: {NAME}", True),
        (f"mcp-name: {NAME}-->", True),
        (f"mcp-name: {NAME}--!>", True),  # comment close the docs do not mention
        (f"(mcp-name: {NAME})", True),  # ')' is not a name character
        (f"mcp-name: {NAME}, and more", True),
        (f'"mcp-name: {NAME}"', True),
        (f"mcp-name: {NAME}" + chr(0xE9), True),  # non-ASCII ends the name
        (f"mcp-name: {NAME}.", False),  # '.' is a name character: glued
        (f"mcp-name: {NAME}_x", False),
        (f"mcp-name: {NAME}/x", False),
        (f"mcp-name: {NAME}-pro", False),  # a longer name
        (f"mcp-name:  {NAME}", False),  # two spaces
        (f"mcp-name:\t{NAME}", False),
        (f"MCP-NAME: {NAME}", False),
        (f"mcp-name: {NAME.replace('kimmawla', 'KimMawla')}", False),
        (f"mcp-name: {NAME}-pro mcp-name: {NAME} ", True),  # a later occurrence counts
    ],
)
def test_pypi_marker_matches_verifier(description, expected):
    assert has_pypi_marker(description, NAME) is expected


ENTRY_NORM = {
    "name": NAME,
    "packages": [{"registry_type": "npm", "identifier": "x", "version": "1.0.0"}],
}


@pytest.mark.parametrize(
    ("mcp_name", "title"),
    [
        (NAME, None),
        ("", "npm package has no mcpName for this server"),  # empty counts as missing
        (None, "npm package has no mcpName for this server"),
        (
            NAME.upper(),
            "npm package's mcpName names a different server",
        ),  # case-sensitive
        (NAME + " ", "npm package's mcpName names a different server"),
    ],
)
def test_npm_mcp_name_matches_verifier(mcp_name, title):
    meta = {"package_exists": True, "version_exists": True, "mcp_name": mcp_name}
    findings = rg005_ownership_marker(ENTRY_NORM, 0, meta)
    assert [f.title for f in findings] == (
        [RG005_TITLE_PREFIX + title] if title else []
    )


def mcpb(identifier, sha="a" * 64, base=None):
    return {
        "name": NAME,
        "packages": [
            {
                "registry_type": "mcpb",
                "identifier": identifier,
                "version": None,
                "file_sha256": sha,
                "registry_base_url": base,
            }
        ],
    }


GH = "https://github.com/kimmawla/tool/releases/download/v1/server.mcpb"


@pytest.mark.parametrize(
    ("entry", "problems"),
    [
        (mcpb(GH), []),
        (
            mcpb("https://GITHUB.com/kimmawla/Tool/releases/download/v1/x.MCPB"),
            [],
        ),  # 'mcp' any case
        (mcpb("https://github.com/kimmawla/MCP-tool/releases/download/v1/x.bin"), []),
        (mcpb("https://gitlab.com/group/sub/mcp/-/releases/v1/downloads/x.bin"), []),
        (mcpb("https://gitlab.com/group/mcp/-/package_files/42/download"), []),
        (mcpb(GH, sha="NOT-A-HASH"), []),  # format is not checked on publish
        (mcpb(GH, sha=""), ["no fileSha256"]),
        (mcpb(GH, sha=None), ["no fileSha256"]),
        (mcpb(GH, base="https://github.com"), ["registryBaseUrl"]),
        (
            mcpb("https://github.com/kimmawla/tool/releases/download/v1/x.bin"),
            ["does not contain 'mcp'"],
        ),
        (
            mcpb("http://github.com/kimmawla/mcp/releases/download/v1/x.mcpb"),
            ["does not use https"],
        ),
        (
            mcpb("https://github.com:443/kimmawla/mcp/releases/download/v1/x.mcpb"),
            ["not hosted"],
        ),
        (mcpb("https://evil.example/mcp/releases/download/v1/x.mcpb"), ["not hosted"]),
        (
            mcpb("https://github.com/kimmawla/mcp/archive/v1.zip"),
            ["not a GitHub release asset"],
        ),
        (
            mcpb("https://github.com/-bad/mcp/releases/download/v1/x.mcpb"),
            ["not a GitHub release asset"],
        ),
        (
            mcpb(GH + "\n"),
            ["not a valid URL"],
        ),  # Go's url.Parse rejects control characters
        (
            mcpb("https://github.com/kimmawla/mcp/releases/download/v1/x%zz.mcpb"),
            ["not a valid URL"],
        ),
        (
            mcpb("https://github.com/kimmawla/mcp/releases/download/v1/a%2Fb.mcpb"),
            ["not a GitHub release asset"],
        ),
    ],
)
def test_mcpb_static_matches_verifier(entry, problems):
    titles = [f.title for f in rg005_mcpb_static(entry, 0)]
    assert len(titles) == len(problems)
    for title, expected in zip(titles, problems, strict=True):
        assert expected in title


# --- registry name lookup is case-sensitive


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def fake_sleep(delay):
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)


@pytest_asyncio.fixture
async def http():
    async with HttpClient() as client:
        yield client


@pytest.mark.asyncio
async def test_wrong_case_name_is_not_found(http):
    with respx.mock() as router:
        route = router.get(url__regex=REGISTRY_RE).mock(
            return_value=httpx.Response(
                404, json=load("registry_server_not_found.json")
            )
        )
        with pytest.raises(ToolError, match="no entry with that name"):
            await audit_registry_entry("io.github.KimMawla/vuln-triage-mcp", http)
        assert (
            b"io.github.KimMawla%2Fvuln-triage-mcp"
            in route.calls.last.request.url.raw_path
        )


@pytest.mark.asyncio
async def test_registry_answer_in_other_case_is_rejected(http):
    entry = copy.deepcopy(ENTRY)
    entry["server"]["name"] = "io.github.KimMawla/vuln-triage-mcp"
    with respx.mock() as router:
        router.get(url__regex=REGISTRY_RE).mock(
            return_value=httpx.Response(200, json=entry)
        )
        with pytest.raises(ToolError, match="no checks ran"):
            await audit_registry_entry(NAME, http)


# --- OWASP table


def owasp_table() -> dict[str, tuple[str, ...]]:
    text = (ROOT / "docs/rules-registry.md").read_text(encoding="utf-8")
    section = text.split("## OWASP MCP Top 10 mapping", 1)[1]
    rows = re.findall(
        r"^\| (RG\d{3}(?: \w+)?) \| (MCP\d\d:\d{4}(?:, MCP\d\d:\d{4})*) \| (.+) \|$",
        section,
        re.MULTILINE,
    )
    assert all(r[2].strip() for r in rows), "every row needs a rationale"
    return {rule: tuple(ids.split(", ")) for rule, ids, _ in rows}


def test_owasp_table_matches_code_and_owasp_ids():
    table = owasp_table()
    assert table == dict(RULE_OWASP)
    for ids in table.values():
        for owasp_id in ids:
            assert owasp_id in OWASP_MCP_TOP_10
