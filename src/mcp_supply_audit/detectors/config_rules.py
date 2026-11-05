"""CF001-CF007: pure functions over one normalized server from an MCP client config. Rules
live in docs/rules-config.md; read it before changing this. Client formats and runner syntax
are in docs/api-notes.md ("MCP client configs and package runners"). Servers come from
config_scan.py.

The config may hold real secrets, so no value from it ever reaches a Finding. Evidence is
built only by config_evidence (the part of the entry, a key name or argument position, the
server name) and, for URLs, registry_rules.url_evidence (scheme, host, port); a static test
checks that every CF rule passes evidence from these builders and nothing else. Titles and
locations are written here and never contain target text.

Each rule returns a list of Findings, or a Skip carrying a reason from the fixed set and an
optional fixed detail.
"""

import functools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from mcp_supply_audit.detectors.registry_rules import (
    _credential_names,
    _param_key,
    _path_segments,
    _query_pairs,
    _split_url,
    url_evidence,
)
from mcp_supply_audit.detectors.tool_defs import RuleDataError, load_rule_data
from mcp_supply_audit.findings import (
    Confidence,
    Finding,
    Severity,
    SkipDetail,
    SkipReason,
)
from mcp_supply_audit.secrets import find_secrets, scrub


@dataclass(frozen=True)
class Server:
    """One server entry, normalized by config_scan.py. Everything but the index is target
    text, and kept out of repr."""

    index: int
    name: str = field(repr=False)
    type: str | None = field(repr=False)
    command: str | None = field(repr=False)
    args: tuple[str, ...] = field(repr=False)
    env: tuple[tuple[str, str | None], ...] = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    url: str | None = field(repr=False)
    # Cursor's static OAuth settings (string fields only, e.g. CLIENT_SECRET).
    auth: tuple[tuple[str, str], ...] = field(repr=False)
    # Names of the documented fields present with a non-null value (config_scan.KNOWN_FIELDS);
    # names only, never values.
    fields: frozenset[str] = field(default=frozenset(), repr=False)


@dataclass(frozen=True)
class Skip:
    reason: SkipReason
    detail: SkipDetail | None = None


RuleResult = list[Finding] | Skip

RULE_IDS: Final = ("CF001", "CF002", "CF003", "CF004", "CF005", "CF006", "CF007")

_O_SUPPLY: Final = ("MCP04:2025",)
_O_SECRETS: Final = ("MCP01:2025",)
_O_EXEC: Final = ("MCP05:2025",)
_O_SCOPE: Final = ("MCP02:2025",)

# OWASP MCP Top 10 per rule; docs/rules-config.md has the same table with a rationale per
# row (tests compare them, and check the ids against owasp.py).
RULE_OWASP: Final[Mapping[str, tuple[str, ...]]] = {
    "CF001": _O_SUPPLY,
    "CF002": _O_SECRETS,
    "CF003": _O_SECRETS,
    "CF004": _O_EXEC,
    "CF005": _O_SCOPE,
    "CF006": _O_SUPPLY,
    "CF007 execution": _O_EXEC,
    "CF007 transport": _O_SECRETS,
}


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    owasp: tuple[str, ...],
    location: str,
    evidence: str,
    remediation: str,
) -> Finding:
    # A secret-shaped server or key name never reaches a Finding either (secrets.py).
    evidence, start = scrub(evidence)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        owasp=owasp,
        location=location,
        evidence=evidence,
        remediation=remediation,
        evidence_start=start,
    )


# --- evidence

EVIDENCE_PARTS: Final = frozenset({"args", "env", "headers", "url", "auth", "field"})
# Server and key names are capped before they reach evidence, so the part and position
# always fit in the 120-character snippet.
_NAME_MAX: Final = 40
_ELLIPSIS: Final = "..."


def _capped(text: str) -> str:
    return text if len(text) <= _NAME_MAX else text[:_NAME_MAX] + _ELLIPSIS


def config_evidence(
    server: Server, part: str, key: str | int | None = None, url: str | None = None
) -> str:
    """The only evidence CF rules show: the part of the entry, a key name or argument
    position, the scheme/host/port of a URL (url_evidence), and the server name. Never a
    value, a URL path or query, or userinfo. Part "field" names a whole field and the
    server's index: "field headersHelper; servers[2]; server <name>"."""
    if part not in EVIDENCE_PARTS:
        raise ValueError(f"unknown evidence part {part!r}")
    if isinstance(key, bool):
        raise TypeError("key must be a key name or an argument position")
    where = part
    if part == "field":
        if not isinstance(key, str):
            raise TypeError("a field needs its name")
        where = f"field {_capped(key)}; servers[{server.index}]"
    elif isinstance(key, int):
        where += f"[{key}]"
    elif key is not None:
        where += f" key {_capped(key)}"
    if url is not None:
        where += f" {url_evidence(url)}"
    return f"{where}; server {_capped(server.name)}"


def _location(server: Server, part: str, position: int | None = None) -> str:
    suffix = f"[{position}]" if position is not None else ""
    return f"servers[{server.index}].{part}{suffix}"


# --- values: placeholders and credential names

# ${VAR}, ${VAR:-default} (Claude Code, VS Code portable), ${env:NAME}, ${input:id},
# ${userHome}, ... (Cursor, VS Code). Only a :- default is literal text.
_VARIABLE: Final = re.compile(r"\$\{([^{}]*)\}")
# <your-key> style placeholders: not client syntax, but what docs and templates use.
_ANGLE: Final = re.compile(r"<[^<>]*>")
_AUTH_SCHEME: Final = re.compile(r"^(?:bearer|basic|token)(?:\s+|$)", re.IGNORECASE)


def _default_or_empty(match: re.Match[str]) -> str:
    _, sep, default = match.group(1).partition(":-")
    return default if sep else ""


def literal_text(value: str) -> str:
    """The part of a value that is literal: variables removed (their :- defaults kept) and
    <...> placeholders removed."""
    return _ANGLE.sub("", _VARIABLE.sub(_default_or_empty, value))


def has_literal(value: str) -> bool:
    """True if the value holds literal text beyond placeholders and an auth scheme word.
    "${TOKEN}", "Bearer ${env:TOKEN}", "<your-key>", "..." and "" do not."""
    rest = _AUTH_SCHEME.sub("", literal_text(value).strip())
    return any(c.isalnum() for c in rest)


def is_placeholder(value: str) -> bool:
    return bool(_VARIABLE.search(value)) or "{" in value


def credential_name(key: str, names: frozenset[str]) -> bool:
    """A listed name (rg011_credential_params.yaml) as the whole key or as its last
    `_`/`-`-separated part: API_TOKEN, X-Api-Key, --auth-token. Leading dashes (argument
    flags) are ignored. URL query parameters use the whole-name rule of RG011 instead."""
    k = _param_key(key).lstrip("-")
    if k in names:
        return True
    return any(k.endswith(sep + n) for n in names for sep in ("_", "-"))


# --- rule data


@dataclass(frozen=True)
class Runner:
    id: str
    commands: frozenset[str]
    subcommand: tuple[str, ...]
    ecosystem: str
    pin: str
    package_options: frozenset[str]
    extra_package_options: frozenset[str]
    flag_options: frozenset[str]
    shell_options: frozenset[str]
    positional: str


def _strings(filename: str, entry: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = entry.get(key)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleDataError(f"{filename}: {key} must be a list of strings")
    return tuple(value)


def _entries(filename: str, key: str) -> list[Mapping[str, Any]]:
    entries = load_rule_data(filename).get(key)
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise RuleDataError(f"{filename}: {key} must be a list of mappings")
    return entries


def _choice(
    filename: str, entry: Mapping[str, Any], key: str, allowed: set[str]
) -> str:
    value = entry.get(key)
    if value not in allowed:
        raise RuleDataError(f"{filename}: {key} must be one of {sorted(allowed)}")
    return value


@functools.cache
def runners() -> tuple[Runner, ...]:
    f = "config_runners.yaml"
    out = []
    for e in _entries(f, "runners"):
        if not isinstance(e.get("id"), str):
            raise RuleDataError(f"{f}: id must be a string")
        out.append(
            Runner(
                id=e["id"],
                commands=frozenset(_strings(f, e, "commands")),
                subcommand=_strings(f, e, "subcommand"),
                ecosystem=_choice(f, e, "ecosystem", {"npm", "pypi"}),
                pin=_choice(f, e, "pin", {"exact", "floating_only"}),
                package_options=frozenset(_strings(f, e, "package_options")),
                extra_package_options=frozenset(
                    _strings(f, e, "extra_package_options")
                ),
                flag_options=frozenset(_strings(f, e, "flag_options")),
                shell_options=frozenset(_strings(f, e, "shell_options")),
                positional=_choice(
                    f, e, "positional", {"name_at_version", "requirement"}
                ),
            )
        )
    return tuple(out)


@dataclass(frozen=True)
class Shell:
    name: str
    commands: frozenset[str]
    flags: frozenset[str]
    clustered: bool
    case_insensitive: bool
    script_file_flags: frozenset[str]


@dataclass(frozen=True)
class ShellData:
    shells: tuple[Shell, ...]
    download_pipe: re.Pattern[str]
    command_fields: tuple[str, ...]


@functools.cache
def shell_data() -> ShellData:
    f = "config_shells.yaml"
    shells = []
    for e in _entries(f, "shells"):
        if not isinstance(e.get("name"), str) or not all(
            isinstance(e.get(k), bool) for k in ("clustered", "case_insensitive")
        ):
            raise RuleDataError(
                f"{f}: shell entries need name, clustered, case_insensitive"
            )
        fold = str.lower if e["case_insensitive"] else str
        shells.append(
            Shell(
                name=e["name"],
                commands=frozenset(_strings(f, e, "commands")),
                flags=frozenset(fold(x) for x in _strings(f, e, "flags")),
                clustered=e["clustered"],
                case_insensitive=e["case_insensitive"],
                script_file_flags=frozenset(
                    fold(x) for x in _strings(f, e, "script_file_flags")
                ),
            )
        )
    data = load_rule_data(f)
    downloaders = _strings(f, data, "downloaders")
    interpreters = _strings(f, data, "interpreters")
    if not downloaders or not interpreters:
        raise RuleDataError(f"{f}: downloaders and interpreters must not be empty")
    get = "|".join(re.escape(d) for d in downloaders)
    run = "|".join(re.escape(i) for i in interpreters)
    pattern = re.compile(
        # curl URL | sh   ...   | sudo /bin/bash
        rf"\b(?:{get})\b[^|]*\|\s*(?:sudo\s+)?(?:[\w./-]*/)?(?:{run})\b"
        # iex (irm URL)   iex(New-Object Net.WebClient).DownloadString(URL)
        rf"|\b(?:{run})\b[\s(]*[^|;]*?\b(?:{get})\b"
        # bash <(curl URL)   sh -c "$(curl URL)"
        rf"|\b(?:{run})\b[^|;]*?(?:<\(|\$\()\s*(?:{get})\b",
        re.IGNORECASE,
    )
    return ShellData(tuple(shells), pattern, _strings(f, data, "command_fields"))


@dataclass(frozen=True)
class RiskyEnv:
    category: str
    values: frozenset[str] | None


@functools.cache
def risky_env() -> Mapping[str, RiskyEnv]:
    f = "config_env_risky.yaml"
    out = {}
    for e in _entries(f, "entries"):
        if not isinstance(e.get("name"), str):
            raise RuleDataError(f"{f}: name must be a string")
        values = (
            frozenset(v.lower() for v in _strings(f, e, "values"))
            if "values" in e
            else None
        )
        out[e["name"].lower()] = RiskyEnv(
            _choice(f, e, "category", {"execution", "transport"}), values
        )
    return out


# --- runners and package specs (CF001, CF006)


def command_name(command: str) -> str:
    """Basename, lower-cased, without .exe or .cmd: /usr/bin/NPX.cmd -> npx."""
    base = re.split(r"[\\/]", command)[-1].lower()
    for ext in (".exe", ".cmd"):
        base = base.removesuffix(ext)
    return base


def _runner_for(server: Server) -> tuple[Runner, int] | None:
    """The runner the server's command is, and where its own arguments start."""
    if server.command is None:
        return None
    name = command_name(server.command)
    for runner in runners():
        if name not in runner.commands:
            continue
        n = len(runner.subcommand)
        if tuple(a.lower() for a in server.args[:n]) == runner.subcommand:
            return runner, n
    return None


@dataclass(frozen=True)
class _Spec:
    position: int  # index in args
    form: str  # "name_at_version" or "requirement"
    text: str = field(repr=False)


def _package_specs(
    runner: Runner, args: Sequence[str], start: int
) -> list[_Spec] | None:
    """Every package the runner is given, or None if an option or form is undocumented."""
    option_form = "name_at_version" if runner.ecosystem == "npm" else "requirement"
    specs: list[_Spec] = []
    replaced = False
    i = start
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            break
        if not arg.startswith("-"):
            break
        name, eq, value = arg.partition("=")
        if name in runner.package_options or name in runner.extra_package_options:
            if eq:
                specs.append(_Spec(i, option_form, value))
                i += 1
            elif i + 1 < len(args):
                specs.append(_Spec(i + 1, option_form, args[i + 1]))
                i += 2
            else:
                return None
            replaced = replaced or name in runner.package_options
            continue
        if arg in runner.flag_options:
            i += 1
            continue
        return None  # a shell-string option, or one the runner's docs do not cover
    if not replaced:
        # With --package / --from / --spec, the positional is a command, not a package.
        if i >= len(args):
            return None
        specs.append(_Spec(i, runner.positional, args[i]))
    return specs


_DRIVE: Final = re.compile(r"^[A-Za-z]:[\\/]")
_ARCHIVE_SUFFIXES: Final = (".tgz", ".tar.gz", ".tar", ".whl", ".zip")


def source_kind(spec: str, ecosystem: str) -> str | None:
    """ "git URL", "tarball URL", "local path", or None for a registry name (CF006).
    Forms are the ones npm's package-spec and package.json pages, uv and pipx document."""
    s = spec.strip()
    if ecosystem == "pypi" and " @ " in s:  # PEP 508 direct reference: name @ URL
        s = s.split(" @ ", 1)[1].strip()
    if ecosystem == "npm":
        at = s.find("@", 1) if s.startswith("@") else s.find("@")
        if at != -1 and s[at + 1 :].startswith("npm:"):  # alias@npm:<name>
            return source_kind(s[at + 5 :], ecosystem)
    low = s.lower()
    if low.startswith(("git+", "git://", "git@", "github:")):
        return "git URL"
    if "://" in s:
        return "tarball URL" if ecosystem == "npm" else "archive URL"
    if s in (".", "..") or s.startswith(("./", "../", "/", "~/", ".\\", "..\\")):
        return "local path"
    if _DRIVE.match(s) or low.endswith(_ARCHIVE_SUFFIXES):
        return "local path"
    if ecosystem == "npm" and not s.startswith("@") and "/" in s.split("#", 1)[0]:
        return "git URL"  # GitHub shorthand user/repo
    return None


# Outcomes of _pin: an exact pin, a fixed phrase saying why it is not one, or undetermined.
_PINNED: Final = "pinned"
_UNDETERMINED: Final = "undetermined"

_SEMVER: Final = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)
_SEMVER_EXACT: Final = re.compile(_SEMVER)
_SEMVER_LOOSE: Final = re.compile(rf"[v=]\s*{_SEMVER}")
_REQUIREMENT: Final = re.compile(
    r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)", re.DOTALL
)


def _npm_pin(runner: Runner, spec: str) -> str:
    at = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    version = spec[at + 1 :] if at != -1 else ""
    if version.startswith("npm:"):  # alias@npm:<name>[@<version>]
        return _npm_pin(runner, version[4:])
    if not version:
        return "no version"
    if version.lower() == "latest":
        return "the latest tag"
    if runner.pin == "floating_only":
        return _UNDETERMINED
    if version.startswith("catalog:") or _SEMVER_LOOSE.fullmatch(version):
        return _UNDETERMINED
    if _SEMVER_EXACT.fullmatch(version):
        return _PINNED
    return "a range or tag"


def _pypi_at_pin(spec: str) -> str:
    if any(c in spec for c in "=<>~!"):
        return _UNDETERMINED  # a specifier as the positional: not documented for uvx
    _, at, version = spec.partition("@")
    if not at:
        return "no version"
    if version.strip().lower() == "latest":
        return "the latest tag"
    return _PINNED if version.strip() else _UNDETERMINED


def _requirement_pin(spec: str) -> str:
    if "@" in spec:
        return _UNDETERMINED
    match = _REQUIREMENT.fullmatch(spec.strip())
    if match is None:
        return _UNDETERMINED
    specifier = match.group(3).split(";", 1)[0].strip()
    if not specifier:
        return "no version"
    if "===" in specifier:
        return _UNDETERMINED
    clauses = [c.strip() for c in specifier.split(",")]
    if (
        len(clauses) == 1
        and clauses[0].startswith("==")
        and "*" not in clauses[0]
        and clauses[0][2:].strip()
    ):
        return _PINNED
    return "a range"


def _pin(runner: Runner, spec: _Spec) -> str:
    if is_placeholder(spec.text):
        return _UNDETERMINED
    if runner.ecosystem == "npm":
        return _npm_pin(runner, spec.text.strip())
    if spec.form == "name_at_version":
        return _pypi_at_pin(spec.text.strip())
    return _requirement_pin(spec.text)


def cf001_runner_pin(server: Server) -> RuleResult:
    """CF001: a package runner runs a package without an exact version pin."""
    match = _runner_for(server)
    if match is None:
        return Skip(SkipReason.NOT_APPLICABLE)
    runner, start = match
    specs = _package_specs(runner, server.args, start)
    if specs is None:
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.RUNNER_SYNTAX)
    findings = []
    undetermined: SkipDetail | None = None
    for spec in specs:
        if source_kind(spec.text, runner.ecosystem) is not None:
            continue  # not a registry name: CF006
        outcome = _pin(runner, spec)
        if outcome == _UNDETERMINED:
            undetermined = undetermined or (
                SkipDetail.PLACEHOLDER
                if is_placeholder(spec.text)
                else SkipDetail.RUNNER_SYNTAX
            )
            continue
        if outcome == _PINNED:
            continue
        position = spec.position
        findings.append(
            _finding(
                "CF001",
                f"Package runner ({runner.id}) runs a package with {outcome}, "
                "not an exact version",
                Severity.MEDIUM,
                Confidence.HIGH,
                RULE_OWASP["CF001"],
                _location(server, "args", position),
                config_evidence(server, "args", position),
                "Pin the exact version the runner documents (e.g. pkg@1.2.3 or "
                "pkg==1.2.3), so a new release is not installed without review.",
            )
        )
    if not findings and undetermined is not None:
        return Skip(SkipReason.NOT_DETERMINABLE, undetermined)
    return findings


def cf006_package_source(server: Server) -> RuleResult:
    """CF006: the runner's package is a git URL, a tarball or archive URL, or a local path."""
    match = _runner_for(server)
    if match is None:
        return Skip(SkipReason.NOT_APPLICABLE)
    runner, start = match
    specs = _package_specs(runner, server.args, start)
    if specs is None:
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.RUNNER_SYNTAX)
    findings = []
    for spec in specs:
        kind = source_kind(spec.text, runner.ecosystem)
        if kind is None:
            continue
        position = spec.position
        url = spec.text.split(" @ ", 1)[-1].strip() if "://" in spec.text else None
        findings.append(
            _finding(
                "CF006",
                f"Package runner ({runner.id}) installs from a {kind}, "
                "not a registry name",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                RULE_OWASP["CF006"],
                _location(server, "args", position),
                config_evidence(server, "args", position, url=url),
                "Install a published, versioned package from the registry, or review "
                "exactly what this source contains.",
            )
        )
    return findings


# --- remote URL (CF002)

_LOOPBACK_V4: Final = re.compile(r"127(?:\.[0-9]{1,3}){3}")
_LOOPBACK_NAMES: Final = frozenset({"localhost", "[::1]"})
# wss is TLS (Claude Code's ws type); unix:// and pipe:// are VS Code's local transports.
_SECURE_OR_LOCAL: Final = frozenset({"https", "wss", "unix", "pipe"})


def cf002_remote_https(server: Server) -> RuleResult:
    """CF002: a remote url whose scheme is not https (or wss), other than loopback."""
    url = server.url
    if url is None:
        return Skip(SkipReason.NOT_APPLICABLE)
    parts = _split_url(url)
    if is_placeholder(parts.scheme or "") or is_placeholder(parts.host):
        return Skip(SkipReason.NOT_DETERMINABLE, SkipDetail.PLACEHOLDER)
    scheme = (parts.scheme or "").lower()
    if scheme in _SECURE_OR_LOCAL:
        return []
    host = parts.host.lower()
    if not parts.ambiguous and (
        host in _LOOPBACK_NAMES or _LOOPBACK_V4.fullmatch(host)
    ):
        return []
    return [
        _finding(
            "CF002",
            "Remote server URL does not use https",
            Severity.HIGH,
            Confidence.HIGH,
            RULE_OWASP["CF002"],
            _location(server, "url"),
            config_evidence(server, "url", url=url),
            "Use an https URL; plain http exposes tokens and tool traffic in transit.",
        )
    ]


# --- credentials (CF003)

_CF003_REMEDIATION: Final = (
    "Move the secret out of the config: reference an environment variable or an input "
    "prompt (e.g. ${API_TOKEN}) and rotate the exposed value."
)


def _credential_args(args: Sequence[str], names: frozenset[str]) -> list[int]:
    """Positions of literal values given to credential-named flags: --token=V or --token V."""
    positions = []
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            continue
        flag, eq, value = arg.partition("=")
        if not credential_name(flag, names):
            continue
        if eq:
            if has_literal(value):
                positions.append(i)
        elif (
            i + 1 < len(args)
            and not args[i + 1].startswith("-")
            and has_literal(args[i + 1])
        ):
            positions.append(i + 1)
    return positions


def cf003_credentials(server: Server) -> RuleResult:
    """CF003: a credential-looking value in env, headers, auth, args, or the URL's userinfo,
    query or path, by key name or by documented token format. Placeholders do not count."""
    names = _credential_names()
    owasp = RULE_OWASP["CF003"]
    findings = []
    keyed = (("env", server.env), ("headers", server.headers), ("auth", server.auth))
    for part, pairs in keyed:
        for key, value in pairs:
            if value is None:
                continue
            if credential_name(key, names) and has_literal(value):
                findings.append(
                    _finding(
                        "CF003",
                        f"Credential-named {part} entry holds a literal value",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        owasp,
                        _location(server, part),
                        config_evidence(server, part, key),
                        _CF003_REMEDIATION,
                    )
                )
                continue
            for hit in find_secrets(literal_text(value))[:1]:
                findings.append(
                    _finding(
                        "CF003",
                        f"{part} value matches the documented {hit.kind} format",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        owasp,
                        _location(server, part),
                        config_evidence(server, part, key),
                        _CF003_REMEDIATION,
                    )
                )
    by_name = _credential_args(server.args, names)
    for position in by_name:
        findings.append(
            _finding(
                "CF003",
                "Credential-named argument holds a literal value",
                Severity.HIGH,
                Confidence.MEDIUM,
                owasp,
                _location(server, "args", position),
                config_evidence(server, "args", position),
                _CF003_REMEDIATION,
            )
        )
    for position, arg in enumerate(server.args):
        if position in by_name:
            continue
        for hit in find_secrets(literal_text(arg))[:1]:
            findings.append(
                _finding(
                    "CF003",
                    f"Argument matches the documented {hit.kind} format",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    owasp,
                    _location(server, "args", position),
                    config_evidence(server, "args", position),
                    _CF003_REMEDIATION,
                )
            )
    url = server.url
    if url is None:
        return findings
    if has_literal(_split_url(url).userinfo):
        findings.append(
            _finding(
                "CF003",
                "Remote URL embeds credentials (userinfo)",
                Severity.HIGH,
                Confidence.HIGH,
                owasp,
                _location(server, "url"),
                config_evidence(server, "url", url=url),
                _CF003_REMEDIATION,
            )
        )
    for key, value in _query_pairs(url):
        if not has_literal(value):
            continue
        if (
            _param_key(key) in names
        ):  # RG011's whole-name rule: page_token is not a secret
            findings.append(
                _finding(
                    "CF003",
                    "Remote URL embeds a credential parameter",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    owasp,
                    _location(server, "url"),
                    config_evidence(server, "url", key, url=url),
                    _CF003_REMEDIATION,
                )
            )
            continue
        for hit in find_secrets(literal_text(value))[:1]:
            findings.append(
                _finding(
                    "CF003",
                    f"Remote URL query value matches the documented {hit.kind} format",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    owasp,
                    _location(server, "url"),
                    config_evidence(server, "url", key, url=url),
                    _CF003_REMEDIATION,
                )
            )
    for position, segment in enumerate(_path_segments(url)):
        for hit in find_secrets(literal_text(segment))[:1]:
            findings.append(
                _finding(
                    "CF003",
                    f"Remote URL path segment {position} matches the documented "
                    f"{hit.kind} format",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    owasp,
                    _location(server, "url"),
                    config_evidence(server, "url", url=url),
                    _CF003_REMEDIATION,
                )
            )
    return findings


# --- shell wrappers (CF004)


def _shell_for(command: str) -> Shell | None:
    name = command_name(command)
    return next((s for s in shell_data().shells if name in s.commands), None)


def _inline_flag(shell: Shell, args: Sequence[str]) -> int | None:
    """Position of the inline-script flag, if the shell is given one before its script."""
    for i, arg in enumerate(args):
        flag = arg.lower() if shell.case_insensitive else arg
        if flag in shell.flags:
            return i
        if shell.clustered and re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", arg):
            return i
        if flag in shell.script_file_flags:
            return None
        if shell.clustered and not arg.startswith(("-", "+")):
            return None  # sh's first operand is a script file
    return None


def cf004_shell_wrapper(server: Server) -> RuleResult:
    """CF004: a field the client runs as a shell command (config_shells.yaml
    command_fields, e.g. headersHelper) is present; the command is a shell given an inline
    script; and whether that script pipes a download into an interpreter."""
    owasp = RULE_OWASP["CF004"]
    findings = []
    for key in shell_data().command_fields:
        if key not in server.fields:
            continue
        findings.append(
            _finding(
                "CF004",
                f"Client runs the server's {key} field as a shell command",
                Severity.HIGH,
                Confidence.HIGH,
                owasp,
                _location(server, key),
                config_evidence(server, "field", key),
                "Review exactly what this command runs before trusting the config; "
                "prefer static headers with ${VAR} references.",
            )
        )
    if server.command is None:
        return findings or Skip(SkipReason.NOT_APPLICABLE)
    shell = _shell_for(server.command)
    if shell is None:
        return findings
    position = _inline_flag(shell, server.args)
    if position is None:
        return findings
    findings.append(
        _finding(
            "CF004",
            f"Server starts through a shell ({shell.name}) with an inline script",
            Severity.HIGH,
            Confidence.MEDIUM,
            owasp,
            _location(server, "args", position),
            config_evidence(server, "args", position),
            "Run the server's executable directly, with its arguments in args, so no "
            "shell parses them.",
        )
    )
    script = " ".join(server.args[position + 1 :])
    if shell_data().download_pipe.search(script):
        findings.append(
            _finding(
                "CF004",
                "Inline script pipes a download into an interpreter",
                Severity.HIGH,
                Confidence.MEDIUM,
                owasp,
                _location(server, "args", position),
                config_evidence(server, "args", position),
                "Do not run code fetched at start-up; install a pinned, reviewed package.",
            )
        )
    return findings


# --- filesystem scope (CF005)

_HOME_VARIABLES: Final = frozenset(
    {
        "~",
        "$home",
        "${home}",
        "${env:home}",
        "${userhome}",
        "%userprofile%",
        "${env:userprofile}",
        "$env:userprofile",
    }
)
_HOME_DIR: Final = re.compile(
    r"(?:[a-z]:)?/(?:users|home)(?:/[^/]+)?|/root|/var/root", re.IGNORECASE
)
_DRIVE_ROOT: Final = re.compile(r"[A-Za-z]:")


def broad_scope(value: str) -> str | None:
    """ "a filesystem root", "a drive root", "a home directory", or None."""
    v = value.strip().strip("\"'").replace("\\", "/")
    trimmed = v.rstrip("/")
    if v and not trimmed:
        return "a filesystem root"
    if _DRIVE_ROOT.fullmatch(trimmed):
        return "a drive root"
    if trimmed.lower() in _HOME_VARIABLES or _HOME_DIR.fullmatch(trimmed):
        return "a home directory"
    return None


def cf005_broad_path(server: Server) -> RuleResult:
    """CF005: an argument that is a filesystem root, a drive root, or a home directory."""
    if server.command is None:
        return Skip(SkipReason.NOT_APPLICABLE)
    findings = []
    for position, arg in enumerate(server.args):
        if arg.startswith("-"):
            _, eq, value = arg.partition("=")
            if not eq:
                continue
        else:
            value = arg
        scope = broad_scope(value)
        if scope is None:
            continue
        findings.append(
            _finding(
                "CF005",
                f"Path argument grants {scope}",
                Severity.MEDIUM,
                Confidence.LOW,
                RULE_OWASP["CF005"],
                _location(server, "args", position),
                config_evidence(server, "args", position),
                "Give the server only the directories it needs.",
            )
        )
    return findings


# --- runtime environment (CF007)

_CF007_TITLES: Final[Mapping[str, str]] = {
    "execution": "env entry changes what code the server's runtime loads",
    "transport": "env entry redirects traffic or weakens TLS checks",
}


def _passthrough(key: str, value: str) -> bool:
    """PATH: "${PATH}" and the like hand the variable on unchanged."""
    v = value.strip()
    return v in {f"${{{key}}}", f"${{env:{key}}}", f"${key}", f"%{key}%"}


def cf007_risky_env(server: Server) -> RuleResult:
    """CF007: an env entry from config_env_risky.yaml (loader injection, NODE_OPTIONS,
    PYTHONPATH, PATH, proxies, disabled TLS verification)."""
    if not server.env:
        return Skip(SkipReason.NOT_APPLICABLE)
    table = risky_env()
    findings = []
    for key, value in server.env:
        entry = table.get(_param_key(key))
        if entry is None or value is None:
            continue
        if entry.values is not None:
            if literal_text(value).strip().lower() not in entry.values:
                continue
        elif _passthrough(key, value):
            continue
        findings.append(
            _finding(
                "CF007",
                _CF007_TITLES[entry.category],
                Severity.HIGH,
                Confidence.HIGH,
                RULE_OWASP[f"CF007 {entry.category}"],
                _location(server, "env"),
                config_evidence(server, "env", key),
                "Remove this variable from the server's env unless you set it yourself "
                "and know why it is needed.",
            )
        )
    return findings
