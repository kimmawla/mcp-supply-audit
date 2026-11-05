"""secrets.py detectors, the no-token-literals repo scan, URL display, RG005 wording, and the
drift script. Every token-shaped value is built by concatenation, so no file in the repo
contains one (the repo scan below enforces that)."""

import ast
import importlib.util
import json
import re
from pathlib import Path

import pytest

from mcp_supply_audit.detectors.registry_rules import (
    RG005_REMEDIATION,
    VERIFIER_COMMIT,
    display_url,
    rg001_repository_consistent,
    rg002_owner_match,
    rg005_mcpb_static,
    rg005_ownership_marker,
    rg006_status,
)
from mcp_supply_audit.findings import build_report
from mcp_supply_audit.registry_audit import run_registry_rules
from mcp_supply_audit.secrets import SECRET_FORMATS, find_secrets, scrub

ROOT = Path(__file__).resolve().parents[1]
NAME = "io.github.kimmawla/vuln-triage-mcp"

# Built from parts; never written whole anywhere.
GITHUB = "gh" + "p_" + "A1b2" * 9
GITHUB_FINE = "github" + "_pat_" + "B" * 22 + "_" + "c" * 30
GITLAB = "gl" + "pat-" + "x" * 20
SLACK = "xox" + "b-" + "1234-" * 3 + "abcdef"
STRIPE = "sk" + "_live_" + "Z" * 24
AWS = "AK" + "IA" + "QWERTYUIOP123456"
SAMPLES = {
    "GitHub token": [GITHUB, GITHUB_FINE],
    "GitLab token": [GITLAB],
    "Slack token": [SLACK],
    "Stripe secret key": [STRIPE],
    "AWS access key id": [AWS],
}
ALL_SAMPLES = [v for values in SAMPLES.values() for v in values]


# --- detectors


@pytest.mark.parametrize(
    ("kind", "value"), [(k, v) for k, vs in SAMPLES.items() for v in vs]
)
def test_each_documented_format_is_found(kind, value):
    hits = find_secrets(f"before {value} after")
    assert [(h.kind, h.start, h.end) for h in hits] == [(kind, 7, 7 + len(value))]


@pytest.mark.parametrize(
    "text",
    [
        "page_token=abc&next_token=xyz",
        "gh" + "p_" + "short",  # body too short
        "AK" + "IA",  # prefix alone
        "ASIAN AK" + "IAS",
        "pk" + "_live_" + "Z" * 24,  # Stripe publishable keys are documented as safe
        "x" + "gh" + "p_" + "A" * 36,  # prefix inside a longer word
        "mcp-server-1.2.3",
        "io.github.kimmawla/vuln-triage-mcp",
    ],
)
def test_benign_text_is_not_flagged(text):
    assert find_secrets(text) == []


def test_every_format_cites_its_provider_doc():
    for fmt in SECRET_FORMATS:
        assert fmt.doc_url.startswith("https://")


def test_scrub_replaces_values_and_maps_offsets():
    text = f"a {GITHUB} b {AWS} c"
    scrubbed, offset = scrub(text, text.index(" c"))
    assert scrubbed == "a <redacted> b <redacted> c"
    assert scrubbed[offset:] == " c"
    for value in ALL_SAMPLES:
        assert value not in scrub(f"x {value} y")[0]


# --- no token-shaped literal anywhere in the repo


SCANNED = ("src", "tests", "scripts", "docs")
SKIP_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache"}


def test_repo_contains_no_token_shaped_literals():
    hits = []
    for top in SCANNED:
        for path in (ROOT / top).rglob("*"):
            if (
                not path.is_file()
                or SKIP_PARTS & set(path.parts)
                or path.suffix == ".pyc"
            ):
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
            hits += [
                f"{path.relative_to(ROOT)}:{h.start} {h.kind}"
                for h in find_secrets(text)
            ]
    assert hits == []


def test_repo_scan_would_catch_a_literal(tmp_path):
    planted = tmp_path / "leak.py"
    planted.write_text(f'TOKEN = "{GITHUB}"\n', encoding="utf-8")
    assert find_secrets(planted.read_text(encoding="utf-8"))


# --- RG011 value shapes, never echoed


def remote_entry(url):
    return {
        "name": NAME,
        "version": "0.1.0",
        "repository_url": "https://github.com/kimmawla/vuln-triage-mcp",
        "packages": [],
        "remotes": [{"type": "streamable-http", "url": url, "variables": ()}],
        "status": "active",
        "status_message": None,
        "meta_shape": "nested",
    }


def report_for(entry, metas=()):
    findings, coverage = run_registry_rules(entry, list(metas))
    return build_report(findings, coverage)


@pytest.mark.parametrize(
    ("url", "title", "evidence"),
    [
        (
            f"https://mcp.example.com/mcp?workspace={SLACK}",
            "Remote URL query value matches the documented Slack token format",
            "https://mcp.example.com [parameters: workspace]",
        ),
        (
            f"https://mcp.example.com/v1/{GITHUB}/mcp",
            "Remote URL path segment 1 matches the documented GitHub token format",
            "https://mcp.example.com",
        ),
        (
            "https://mcp.example.com/mcp?k=" + "AK%49A" + AWS[4:],  # percent-encoded
            "Remote URL query value matches the documented AWS access key id format",
            "https://mcp.example.com [parameters: k]",
        ),
    ],
)
def test_value_shapes_flagged_without_echo(url, title, evidence):
    report = report_for(remote_entry(url))
    (finding,) = report.findings
    assert (finding.rule_id, finding.title, finding.evidence) == (
        "RG011",
        title,
        evidence,
    )
    surfaces = [
        json.dumps(report.to_dict()),
        repr(report),
        str(report),
        finding.evidence,
    ]
    for value in ALL_SAMPLES + [AWS[4:]]:
        assert all(value not in s for s in surfaces)


def test_param_flagged_by_name_is_not_flagged_again_by_shape():
    report = report_for(remote_entry(f"https://mcp.example.com/mcp?token={GITHUB}"))
    assert [f.title for f in report.findings] == [
        "Remote URL embeds a credential parameter"
    ]


def test_placeholders_are_not_shape_checked():
    report = report_for(
        remote_entry("https://mcp.example.com/{tenant}/mcp?w={workspace}")
    )
    assert report.findings == ()


# --- display_url: the broader redact list hides, never flags


def test_display_url_hides_redact_list_values_and_secret_shapes():
    url = (
        "https://u:pw@github.com/kimmawla/vuln-triage-mcp?key=k1&session=s1&auth=a1&code=c1"
        "&ref=main#frag"
    )
    shown = display_url(url)
    assert shown == (
        "https://<redacted>@github.com/kimmawla/vuln-triage-mcp?key=<redacted>&session=<redacted>"
        "&auth=<redacted>&code=<redacted>&ref=main#<redacted>"
    )


def test_rg001_and_rg002_evidence_never_show_secrets():
    entry = {
        "name": NAME,
        "repository_url": f"https://user:{STRIPE}@github.com/someone-else/repo?private_token=p1",
        "packages": [{"registry_type": "pypi", "identifier": "x", "version": "1"}],
    }
    meta = {
        "package_exists": True,
        "version_exists": True,
        "repository_urls": ("https://github.com/kimmawla/vuln-triage-mcp",),
    }
    findings = [*rg001_repository_consistent(entry, 0, meta), *rg002_owner_match(entry)]
    assert {f.rule_id for f in findings} == {"RG001", "RG002"}
    for f in findings:
        assert STRIPE not in f.evidence and "p1" not in f.evidence
        assert "private_token=<redacted>" in f.evidence


def test_secret_shaped_status_message_is_scrubbed():
    entry = {
        "status": "deleted",
        "status_message": f"Moved; use key {GITLAB}",
        "meta_shape": "nested",
    }
    (finding,) = rg006_status(entry)
    assert GITLAB not in finding.evidence
    assert finding.evidence == "Moved; use key <redacted>"


# --- RG005 wording


FORBIDDEN_WORDS = re.compile(
    r"\b(accept|accepted|accepts|reject|rejected|rejects|approved|verified by)\b",
    re.IGNORECASE,
)


def rg005_findings():
    npm_entry = {
        "name": NAME,
        "packages": [{"registry_type": "npm", "identifier": "x", "version": "1"}],
    }
    pypi_entry = {
        "name": NAME,
        "packages": [{"registry_type": "pypi", "identifier": "x", "version": "1"}],
    }
    mcpb_entry = {
        "name": NAME,
        "packages": [
            {
                "registry_type": "mcpb",
                "identifier": "http://example.com/x.bin",
                "version": None,
                "file_sha256": None,
                "registry_base_url": "https://example.com",
            }
        ],
    }
    ready = {"package_exists": True, "version_exists": True}
    return [
        *rg005_ownership_marker(npm_entry, 0, {**ready, "mcp_name": None}),
        *rg005_ownership_marker(npm_entry, 0, {**ready, "mcp_name": "io.github.x/y"}),
        *rg005_ownership_marker(pypi_entry, 0, {**ready, "description": "no marker"}),
        *rg005_ownership_marker(
            pypi_entry, 0, {**ready, "description": "mcp-name: io.github.x/y"}
        ),
        *rg005_mcpb_static(mcpb_entry, 0),
    ]


def test_rg005_names_the_published_check_and_commit():
    findings = rg005_findings()
    assert len(findings) == 7
    for f in findings:
        assert f.title.startswith(
            "Does not match the registry's published ownership check"
        )
        assert f"verifier {VERIFIER_COMMIT[:8]}" in f.title
        assert not FORBIDDEN_WORDS.search(f.title), f.title
        assert not FORBIDDEN_WORDS.search(f.remediation), f.remediation
    assert not FORBIDDEN_WORDS.search(RG005_REMEDIATION)


# --- messages and docs


def test_not_found_message_says_names_are_case_sensitive():
    source = (ROOT / "src/mcp_supply_audit/registry_audit.py").read_text(
        encoding="utf-8"
    )
    assert "Names are case-sensitive" in source and "copy the name exactly" in source


def test_known_limits_lists_required_caveats():
    text = (ROOT / "docs/known-limits-registry.md").read_text(encoding="utf-8")
    for needle in (
        "EnableRegistryValidation",
        "fileSha256",
        "registryBaseUrl",
        "github.com:443",
    ):
        assert needle in text


@pytest.mark.parametrize(
    "name", ["rg011_credential_params.yaml", "url_redact_params.yaml"]
)
def test_every_listed_name_has_a_comment(name):
    lines = (
        (ROOT / "src/mcp_supply_audit/data" / name)
        .read_text(encoding="ascii")
        .splitlines()
    )
    entries = [line for line in lines if line.startswith("  - ")]
    assert entries and all("#" in line for line in entries)


def test_flag_list_stays_narrow():
    lines = (
        (ROOT / "src/mcp_supply_audit/data/rg011_credential_params.yaml")
        .read_text()
        .splitlines()
    )
    names = {
        line[4:].split("#")[0].strip() for line in lines if line.startswith("  - ")
    }
    assert not names & {
        "key",
        "session",
        "auth",
        "page",
        "cursor",
        "page_token",
        "session_id",
    }


# --- drift script (dev-only; no network in tests)


def load_script():
    spec = importlib.util.spec_from_file_location(
        "check_registry_drift", ROOT / "scripts/check_registry_drift.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_drift_script_reads_recorded_hashes():
    drift = load_script()
    recorded = drift.recorded_hashes(
        (ROOT / "docs/api-notes.md").read_text(encoding="utf-8")
    )
    assert len(recorded) == 15
    assert "internal/validators/registries/mcpname.go" in recorded


def test_drift_script_reports_changes():
    import hashlib

    drift = load_script()
    same = b"package registries\n"
    recorded = {
        "a.go": hashlib.sha256(same).hexdigest(),
        "b.go": hashlib.sha256(b"old").hexdigest(),
        "c.go": hashlib.sha256(b"gone").hexdigest(),
    }
    files = {"a.go": same, "b.go": b"new", "c.go": None}
    assert drift.compare(recorded, files.get) == {
        "a.go": "unchanged",
        "b.go": "changed",
        "c.go": "missing",
    }


def test_drift_script_not_imported_by_src():
    for path in (ROOT / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [
                    getattr(node, "module", None) or ""
                ]
                assert not any(
                    "check_registry_drift" in n or n.startswith("scripts")
                    for n in names
                )
