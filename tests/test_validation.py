import json

import pytest
from fastmcp.exceptions import ToolError

from mcp_supply_audit.validation import (
    MAX_JSON_DEPTH,
    MAX_TOOLS_LIST_BYTES,
    MIN_SEARCH_TERM_LEN,
    validate_npm_name,
    validate_pypi_name,
    validate_registry_name,
    validate_search_term,
    validate_tools_list_json,
)

NUL = chr(0)
ZWSP = chr(0x200B)
CYRILLIC_A = chr(0x0430)
FULLWIDTH_ZERO = chr(0xFF10)
ARABIC_INDIC_ONE = chr(0x0661)

# Shared hostile inputs; every name validator must reject each with ToolError.
HOSTILE_NAMES = [
    pytest.param("", id="empty"),
    pytest.param("req" + NUL + "uests", id="null-byte"),
    pytest.param("a" * 10_240, id="10kb"),
    pytest.param("req" + ZWSP + "uests", id="zero-width"),
    pytest.param(f"p{CYRILLIC_A}ckage", id="cyrillic-lookalike"),
    pytest.param(f"pkg{FULLWIDTH_ZERO}", id="fullwidth-digit"),
    pytest.param(f"pkg{ARABIC_INDIC_ONE}", id="arabic-indic-digit"),
    pytest.param(None, id="none"),
    pytest.param(123, id="int"),
    pytest.param(["requests"], id="list"),
]


@pytest.mark.parametrize(
    "name",
    ["requests", "Flask", "zope.interface", "typing_extensions", "a", "mcp-server-1"],
)
def test_pypi_valid(name):
    assert validate_pypi_name(f"  {name} ") == name


@pytest.mark.parametrize(
    "name",
    ["-requests", "requests-", ".pkg", "pkg name", "pkg/sub", "pkg@1.0", "a" * 201],
)
def test_pypi_invalid(name):
    with pytest.raises(ToolError):
        validate_pypi_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "express",
        "@types/node",
        "@modelcontextprotocol/sdk",
        "lodash.merge",
        "JSONStream",
        "a",
    ],
)
def test_npm_valid(name):
    assert validate_npm_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        ".hidden",
        "_private",
        "@Scope/pkg",
        "@scope/",
        "@/pkg",
        "a/b",
        "pkg name",
        "node_modules",
        "favicon.ico",
        "a" * 215,
        "../etc",
    ],
)
def test_npm_invalid(name):
    with pytest.raises(ToolError):
        validate_npm_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "io.github.zqvex-owner/weather",
        "io.github.my-org/server.v2",
        "io.github.A1/x_y-z",
        "io.github.Zqvex-Owner/zqvex-land-zoning",
        "io.github.kimmawla/vuln-triage-mcp",
        "com.example/weather",
        "ai.zqvex/zqvex-ai-github",
        "ac.zqvex-inference.sh/mcp",
        "github.zqvex-owner/weather",
        "io.github." + "a" * 40 + "/x",
        "io.github.-octo/weather",  # the schema allows it; so do we
        "a/b",
        "x/" + "y" * 198,  # exactly 200 characters
    ],
)
def test_registry_valid(name):
    assert validate_registry_name(name) == name


def test_registry_name_is_stripped():
    assert (
        validate_registry_name("  io.github.zqvex-owner/weather\n")
        == "io.github.zqvex-owner/weather"
    )


@pytest.mark.parametrize(
    "name",
    [
        "io.github.zqvex-owner",  # no slash
        "io.github.zqvex-owner/",  # empty server name
        "/weather",  # empty namespace
        "io.github.zqvex-owner/a/b",  # two slashes
        "io.github.zqvex-owner//weather",
        "../..",
        "../x",
        "io.github.zqvex-owner/..",
        "io.github.zqvex-owner/.",
        "io.github./weather",  # empty namespace label
        "io..github/weather",
        ".io.github/weather",
        "io.github.zqvex-owner%2Fweather",  # pre-encoded slash
        "io.github.zqvex-owner%2fweather",
        "%2f",
        "io.github.zqvex-owner" + chr(92) + "weather",  # backslash
        "io.github.octo cat/weather",
        "io.github_x/weather",  # '_' is not allowed in the namespace
        "https://registry.modelcontextprotocol.io/v0/servers/x",
        "io.github.zqvex-owner/weather?x=1",
        "io.github.zqvex-owner/weather#x",
        "io.github.zqvex-owner/" + "a" * 200,  # 218 characters
        "x/" + "y" * 199,  # 201 characters
        "a/" + NUL,
        "io.github.zqvex-owner/wea" + NUL + "ther",
    ],
)
def test_registry_invalid(name):
    with pytest.raises(ToolError):
        validate_registry_name(name)


@pytest.mark.parametrize(
    "validator",
    [
        validate_pypi_name,
        validate_npm_name,
        validate_registry_name,
        validate_search_term,
    ],
)
@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_hostile_names_rejected(validator, name):
    with pytest.raises(ToolError) as exc:
        validator(name)
    if isinstance(name, str) and name:
        assert name not in str(exc.value)  # errors never echo input


@pytest.mark.parametrize(
    ("term", "expected"),
    [
        ("vuln-triage", "vuln-triage"),
        ("  EPSS  ", "EPSS"),
        ("abc", "abc"),
        ("io.github.kimmawla/vuln-triage-mcp", "io.github.kimmawla/vuln-triage-mcp"),
    ],
)
def test_search_term_valid(term, expected):
    assert validate_search_term(term) == expected


@pytest.mark.parametrize(
    "term",
    [
        "ab",  # the registry 422s under 3 characters after trimming
        "  ab  ",
        "   ",
        "..",
        "../..",
        "%2f",
        "a%2Fb",
        "vuln triage",
        "x" * (MIN_SEARCH_TERM_LEN - 1),
        "x" * 201,
        "abc" + NUL,
        "<script>",
    ],
)
def test_search_term_invalid(term):
    with pytest.raises(ToolError):
        validate_search_term(term)


SNAPSHOT = {"tools": [{"name": "get_weather", "description": "Forecast [beta] {v2}"}]}


def test_tools_list_accepts_text_and_object():
    assert validate_tools_list_json(json.dumps(SNAPSHOT)) == SNAPSHOT
    assert validate_tools_list_json(SNAPSHOT) is SNAPSHOT


def test_tools_list_oversized_text():
    big = json.dumps({"tools": [], "pad": "x" * MAX_TOOLS_LIST_BYTES})
    with pytest.raises(ToolError, match="too large"):
        validate_tools_list_json(big)


def test_tools_list_oversized_counts_utf8_bytes():
    # Under the cap in characters, over it in UTF-8 bytes.
    big = json.dumps(
        {"pad": chr(0x6771) * (MAX_TOOLS_LIST_BYTES // 2)}, ensure_ascii=False
    )
    assert len(big) < MAX_TOOLS_LIST_BYTES
    with pytest.raises(ToolError, match="too large"):
        validate_tools_list_json(big)


def test_tools_list_oversized_object():
    with pytest.raises(ToolError, match="too large"):
        validate_tools_list_json({"tools": [], "pad": "x" * MAX_TOOLS_LIST_BYTES})


def test_tools_list_error_is_short():
    with pytest.raises(ToolError) as exc:
        validate_tools_list_json("x" * (MAX_TOOLS_LIST_BYTES + 1))
    assert len(str(exc.value)) < 100


@pytest.mark.parametrize("depth", [MAX_JSON_DEPTH + 1, 100_000])
def test_tools_list_deeply_nested_text(depth):
    with pytest.raises(ToolError, match="nested too deeply"):
        validate_tools_list_json("[" * depth + "]" * depth)


def test_tools_list_deeply_nested_object():
    deep: list = []
    for _ in range(100_000):
        deep = [deep]
    with pytest.raises(ToolError, match="nested too deeply"):
        validate_tools_list_json(deep)


def test_tools_list_depth_at_limit_ok():
    text = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
    validate_tools_list_json(text)


def test_brackets_inside_strings_are_not_nesting():
    text = json.dumps({"description": "[" * 10_000 + '\\"{'})
    assert validate_tools_list_json(text)["description"].startswith("[[[")


@pytest.mark.parametrize(
    "snapshot",
    ["not json", "{", "", NUL, '"just a string"', "42", "null", 42, None, b"{}"],
)
def test_tools_list_rejects_non_json_or_scalars(snapshot):
    with pytest.raises(ToolError):
        validate_tools_list_json(snapshot)


def test_tools_list_hostile_content_parses():
    hostile = {"tools": [{"name": "x" + NUL, "description": ZWSP + f"p{CYRILLIC_A}y"}]}
    assert validate_tools_list_json(json.dumps(hostile)) == hostile
