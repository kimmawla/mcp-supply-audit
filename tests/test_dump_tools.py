"""scripts/dump_tools.py runs only the maintainer's two servers. No server is started here:
dump() is replaced in every test that reaches it."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENIGN_FIXTURE = ROOT / "tests/fixtures/tool_defs/benign/vuln_triage_mcp.json"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "dump_tools", ROOT / "scripts/dump_tools.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dt = load_script()


@pytest.fixture
def no_server(monkeypatch):
    """Fail the test if anything tries to start a server."""

    async def refuse(_server):
        raise AssertionError("dump() must not run")

    monkeypatch.setattr(dt, "dump", refuse)


@pytest.fixture
def fake_server(monkeypatch):
    calls = []

    async def fake(server):
        calls.append(server)
        return {"_comment": dt.comment(server), "tools": [{"name": "zqvex-t"}]}

    monkeypatch.setattr(dt, "dump", fake)
    return calls


def test_only_the_two_own_servers_with_fixed_commands():
    assert set(dt.SERVERS) == {"vuln-triage-mcp", "mcp-supply-audit"}
    assert dt.SERVERS["vuln-triage-mcp"] == ("uvx", ("vuln-triage-mcp",))
    command, args = dt.SERVERS["mcp-supply-audit"]
    assert command == "uv" and args[0] == "run" and args[-1] == "mcp-supply-audit"
    assert dt.DEFAULT_SERVER in dt.SERVERS


@pytest.mark.parametrize(
    "argv",
    [
        ["zqvex-other-server"],
        ["--package", "zqvex-other-server"],
        ["vuln-triage-mcp", "--", "sh", "-c", "true"],
        ["vuln-triage-mcp", "extra"],
        ["--command", "uvx"],
    ],
)
def test_refuses_anything_else_and_points_to_the_collector(argv, no_server, capsys):
    assert dt.main(argv) == 2
    err = capsys.readouterr().err
    assert "scripts/collect_tools_list.py" in err


@pytest.mark.parametrize("server", sorted(dt.SERVERS))
def test_default_output_is_under_local_fixtures(
    server, fake_server, tmp_path, monkeypatch
):
    monkeypatch.setattr(dt, "LOCAL_FIXTURES", tmp_path / "local_fixtures")
    out = dt.default_out(server)
    assert out.parent == tmp_path / "local_fixtures"
    assert dt.main([server]) == 0
    assert fake_server == [server]
    raw = out.read_bytes()
    assert raw.isascii()
    assert json.loads(raw)["tools"] == [{"name": "zqvex-t"}]


def test_real_default_points_at_gitignored_local_fixtures():
    assert dt.default_out("vuln-triage-mcp").parent == ROOT / "local_fixtures"
    assert "local_fixtures/" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_no_argument_means_the_default_server(fake_server, tmp_path):
    assert dt.main(["--out", str(tmp_path / "x.json")]) == 0
    assert fake_server == ["vuln-triage-mcp"]


def test_comment_hides_the_checkout_path():
    assert str(ROOT) not in dt.comment("mcp-supply-audit")


def test_committed_benign_fixture_header_matches_the_script():
    doc = json.loads(BENIGN_FIXTURE.read_text(encoding="ascii"))
    assert doc["_comment"].startswith(dt.comment("vuln-triage-mcp"))
    assert "local_fixtures/" in doc["_comment"]
