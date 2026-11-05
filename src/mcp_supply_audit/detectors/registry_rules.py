"""RG001-RG011 (RG007 deferred): pure functions over a normalized registry entry and the
package metadata it points to. Rules live in docs/rules-registry.md; read it before changing
this. Inputs come from clients/registry.py, clients/pypi.py and clients/npm.py.

Each rule returns a list of Findings, or a Skip carrying a reason from the fixed set. Titles
and locations are written here and never contain target text; target text is only evidence,
which Finding.to_dict() renders through evidence_snippet.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import unquote, urlsplit

from mcp_supply_audit.detectors.registry import normalize_repo_url
from mcp_supply_audit.detectors.tool_defs import RuleDataError, load_rule_data
from mcp_supply_audit.findings import Confidence, Finding, Severity, SkipReason
from mcp_supply_audit.hidden_chars import hidden_class
from mcp_supply_audit.secrets import find_secrets, scrub

Entry = Mapping[str, Any]
PackageMeta = Mapping[str, Any]


@dataclass(frozen=True)
class Skip:
    reason: SkipReason


RuleResult = list[Finding] | Skip

SUPPORTED_TYPES: Final = frozenset({"pypi", "npm"})
_GITHUB_NAMESPACE: Final = "io.github."
_GITHUB_HOST: Final = "github.com"

_O_SUPPLY: Final = ("MCP04:2025",)
_O_SECRETS: Final = ("MCP01:2025",)

# OWASP MCP Top 10 per rule; docs/rules-registry.md has the same table with a rationale
# per row (tests compare them, and check the ids against owasp.py).
RULE_OWASP: Final[Mapping[str, tuple[str, ...]]] = {
    "RG001": _O_SUPPLY,
    "RG002": _O_SUPPLY,
    "RG003": _O_SUPPLY,
    "RG004": _O_SUPPLY,
    "RG005": _O_SUPPLY,
    "RG006": _O_SUPPLY,
    "RG008": _O_SUPPLY,
    "RG009": _O_SECRETS,
    "RG010": _O_SUPPLY,
    "RG011 credentials": _O_SECRETS,
    "RG011 port": _O_SUPPLY,
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
    start: int = 0,
) -> Finding:
    # Secret-shaped text never reaches a Finding, whatever the rule (secrets.py).
    evidence, start = scrub(evidence, start)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        owasp=owasp,
        location=f"{location}@{start}",
        evidence=evidence,
        remediation=remediation,
        evidence_start=start,
    )


def _package(entry: Entry, index: int) -> Mapping[str, Any]:
    return entry["packages"][index]


def _package_ready(meta: PackageMeta) -> bool:
    return bool(meta["package_exists"] and meta["version_exists"])


# --- package rules (pypi and npm metadata)


def rg001_repository_consistent(
    entry: Entry, index: int, meta: PackageMeta
) -> RuleResult:
    """RG001: the entry's repository URL matches a repository URL the package declares."""
    if not _package_ready(meta):
        return Skip(SkipReason.NOT_DETERMINABLE)
    entry_url = entry["repository_url"]
    normalized = normalize_repo_url(entry_url)
    declared = {normalize_repo_url(u) for u in meta["repository_urls"]} - {None}
    if normalized is None or not declared:
        return Skip(SkipReason.NOT_DETERMINABLE)
    if normalized in declared:
        return []
    return [
        _finding(
            "RG001",
            "Registry repository URL does not match the package's declared repository",
            Severity.HIGH,
            Confidence.MEDIUM,
            RULE_OWASP["RG001"],
            f"server.repository.url (vs server.packages[{index}])",
            display_url(entry_url),
            "Confirm which repository the package is built from before installing.",
        )
    ]


def rg003_package_exists(entry: Entry, index: int, meta: PackageMeta) -> RuleResult:
    """RG003: the package named in the entry exists in its index."""
    if meta["package_exists"]:
        return []
    return [
        _finding(
            "RG003",
            "Package named in the registry entry does not exist in its index",
            Severity.HIGH,
            Confidence.HIGH,
            RULE_OWASP["RG003"],
            f"server.packages[{index}].identifier",
            _package(entry, index)["identifier"],
            "Do not install; the name could later be registered by anyone.",
        )
    ]


def rg004_version_exists(entry: Entry, index: int, meta: PackageMeta) -> RuleResult:
    """RG004: the listed version exists; a PyPI version with no files is info."""
    if not meta["package_exists"]:
        return Skip(SkipReason.NOT_DETERMINABLE)
    location = f"server.packages[{index}].version"
    version = _package(entry, index)["version"]
    if not meta["version_exists"]:
        return [
            _finding(
                "RG004",
                "Version named in the registry entry does not exist in the package index",
                Severity.MEDIUM,
                Confidence.HIGH,
                RULE_OWASP["RG004"],
                location,
                version,
                "Check which version the publisher intended before installing.",
            )
        ]
    if meta.get("file_count") == 0:
        return [
            _finding(
                "RG004",
                "Version exists in the package index but has no files",
                Severity.INFO,
                Confidence.HIGH,
                RULE_OWASP["RG004"],
                location,
                version,
                "Expect nothing to install for this version; check the publisher's intent.",
            )
        ]
    return []


# The registry verifier these rules mirror (docs/api-notes.md, "Ownership verification code").
VERIFIER_COMMIT: Final = "01e5c936ad3048d16562be503d879e523e36d267"
# RG005 states a mismatch with the published check; it never says what the registry decided.
RG005_TITLE_PREFIX: Final = f"Does not match the registry's published ownership check (verifier {VERIFIER_COMMIT[:8]}): "
RG005_REMEDIATION: Final = (
    "Treat the listing as unverified until the package shows what the registry's published "
    "ownership check looks for."
)

_MARKER: Final = "mcp-name:"
# Verifier source: modelcontextprotocol/registry @ 01e5c936,
# internal/validators/registries/mcpname.go (isServerNameChar, isMCPNameBoundary,
# containsMCPNameToken). Recorded in docs/api-notes.md, "Ownership verification code".
_SERVER_NAME_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-"
)


def _is_marker_boundary(rest: str) -> bool:
    """isMCPNameBoundary: end of text, any character that cannot continue a server name,
    or the start of a comment close (`-->` or `--!>`)."""
    if not rest or rest[0] not in _SERVER_NAME_CHARS:
        return True
    return rest.startswith(("-->", "--!>"))


def has_pypi_marker(description: str, server_name: str) -> bool:
    """containsMCPNameToken: the exact text `mcp-name: <name>` (one space, case-sensitive)
    followed by a boundary. Every occurrence is tried, as the verifier does."""
    needle = f"{_MARKER} {server_name}"
    start = description.find(needle)
    while start != -1:
        if _is_marker_boundary(description[start + len(needle) :]):
            return True
        start = description.find(needle, start + 1)
    return False


def rg005_ownership_marker(entry: Entry, index: int, meta: PackageMeta) -> RuleResult:
    """RG005 for pypi (README marker, registries/pypi.go validatePyPIPackage) and npm
    (mcpName, registries/npm.go validateNPMPackage), on the version the entry lists."""
    if not _package_ready(meta):
        return Skip(SkipReason.NOT_DETERMINABLE)
    name = entry["name"]
    registry_type = _package(entry, index)["registry_type"]
    location = f"server.packages[{index}]"
    remediation = RG005_REMEDIATION
    if registry_type == "npm":
        found = meta["mcp_name"]
        # npm.go: an empty mcpName is "missing"; otherwise an exact, case-sensitive !=.
        if found == name:
            return []
        title = (
            f"{RG005_TITLE_PREFIX}npm package's mcpName names a different server"
            if found
            else f"{RG005_TITLE_PREFIX}npm package has no mcpName for this server"
        )
        return [
            _finding(
                "RG005",
                title,
                Severity.MEDIUM,
                Confidence.HIGH,
                RULE_OWASP["RG005"],
                f"{location} (mcpName)",
                found or "",
                remediation,
            )
        ]
    description = meta["description"] or ""
    if has_pypi_marker(description, name):
        return []
    nearest = description.find(_MARKER)
    if nearest == -1:
        title, evidence, start = (
            f"{RG005_TITLE_PREFIX}PyPI README has no mcp-name marker",
            "",
            0,
        )
    else:
        title, evidence, start = (
            f"{RG005_TITLE_PREFIX}PyPI README's mcp-name marker does not name this server",
            description,
            nearest,
        )
    return [
        _finding(
            "RG005",
            title,
            Severity.MEDIUM,
            Confidence.HIGH,
            RULE_OWASP["RG005"],
            f"{location} (description)",
            evidence,
            remediation,
            start,
        )
    ]


# registries/mcpb.go validateMCPBUrl and isValidGitHubReleaseURL / isValidGitLabReleaseURL.
_MCPB_HOSTS: Final = frozenset(
    {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com"}
)
_MCPB_GITHUB_PATH: Final = re.compile(
    r"/([a-zA-Z0-9]([a-zA-Z0-9\-]{0,37}[a-zA-Z0-9])?)/([a-zA-Z0-9._\-]+)/releases/download/([^/]+)/([^/]+)"
)
_MCPB_GITLAB_PATHS: Final = (
    re.compile(
        r"/([a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9._\-]+)*)/-/releases/([^/]+)/downloads/([^/]+)"
    ),
    re.compile(
        r"/([a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9._\-]+)*)/-/package_files/([0-9]+)/download"
    ),
)
_BAD_ESCAPE: Final = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _mcpb_url_problem(identifier: str) -> str | None:
    """The static part of ValidateMCPB's URL checks, or None if they pass.

    Go's url.Parse decodes the path and rejects malformed escapes; Go's regexp `$` is
    end of text, so fullmatch is used (Python's `$` also matches before a final newline).
    """
    # Go's url.Parse rejects ASCII control characters; Python's urlsplit silently strips
    # some (tab, newline), which would let such a URL pass here but not at the registry.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in identifier):
        return "is not a valid URL"
    try:
        parts = urlsplit(identifier)
    except ValueError:
        return "is not a valid URL"
    host = parts.netloc.rpartition("@")[
        2
    ].lower()  # Go URL.Host: no userinfo, keeps port
    if host not in _MCPB_HOSTS:
        return "is not hosted on github.com or gitlab.com"
    if _BAD_ESCAPE.search(parts.path):
        return "is not a valid URL"
    path = unquote(parts.path)
    if host.endswith("github.com"):
        if not _MCPB_GITHUB_PATH.fullmatch(path):
            return "is not a GitHub release asset URL"
    elif not any(p.fullmatch(path) for p in _MCPB_GITLAB_PATHS):
        return "is not a GitLab release asset URL"
    if parts.scheme != "https":
        return "does not use https"
    if "mcp" not in identifier.lower():
        return "does not contain 'mcp'"
    return None


def rg005_mcpb_static(entry: Entry, index: int) -> RuleResult:
    """RG005 for mcpb: every check registries/mcpb.go ValidateMCPB makes before its HEAD
    request. fileSha256 must be non-empty; its format is not checked on publish."""
    package = _package(entry, index)
    findings = []
    location = f"server.packages[{index}]"

    def add(title: str, field: str, evidence: str, remediation: str) -> None:
        findings.append(
            _finding(
                "RG005",
                title,
                Severity.MEDIUM,
                Confidence.HIGH,
                RULE_OWASP["RG005"],
                f"{location}.{field}",
                evidence,
                remediation,
            )
        )

    if not package["file_sha256"]:
        add(
            f"{RG005_TITLE_PREFIX}MCPB package has no fileSha256",
            "fileSha256",
            "",
            "Do not install an MCPB artifact without a published SHA-256 to check.",
        )
    if package.get("registry_base_url"):
        add(
            f"{RG005_TITLE_PREFIX}MCPB package sets registryBaseUrl",
            "registryBaseUrl",
            display_url(package["registry_base_url"]),
            RG005_REMEDIATION,
        )
    problem = _mcpb_url_problem(package["identifier"])
    if problem is not None:
        add(
            f"{RG005_TITLE_PREFIX}MCPB package URL {problem}",
            "identifier",
            display_url(package["identifier"]),
            RG005_REMEDIATION,
        )
    return findings


# --- entry rules


def rg002_owner_match(entry: Entry) -> RuleResult:
    """RG002: io.github.<owner> matches the owner in a github.com repository URL."""
    name = entry["name"]
    if not name.startswith(_GITHUB_NAMESPACE):
        return Skip(SkipReason.NOT_APPLICABLE)
    url = normalize_repo_url(entry["repository_url"])
    if url is None:
        return Skip(SkipReason.NOT_DETERMINABLE)
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    if parts.hostname != _GITHUB_HOST or not segments:
        return Skip(SkipReason.NOT_DETERMINABLE)
    owner = name[len(_GITHUB_NAMESPACE) :].split("/", 1)[0]
    if owner.casefold() == segments[0].casefold():
        return []
    return [
        _finding(
            "RG002",
            "Registry namespace owner does not match the repository owner",
            Severity.HIGH,
            Confidence.HIGH,
            RULE_OWASP["RG002"],
            "server.repository.url",
            display_url(entry["repository_url"]),
            "Confirm the repository belongs to the namespace owner before installing.",
        )
    ]


def rg006_status(entry: Entry) -> RuleResult:
    """RG006: deleted (removed from the registry) or deprecated."""
    status = entry["status"]
    if entry["meta_shape"] is None or status not in {"active", "deprecated", "deleted"}:
        return Skip(SkipReason.SHAPE_MISMATCH)
    if status == "active":
        return []
    message = entry["status_message"]
    suffix = "" if message else " (no status message)"
    if status == "deleted":
        return [
            _finding(
                "RG006",
                f"Entry removed from the registry{suffix}",
                Severity.HIGH,
                Confidence.MEDIUM,
                RULE_OWASP["RG006"],
                "_meta.statusMessage",
                message or "",
                "Find out why the entry was removed before installing this server.",
            )
        ]
    return [
        _finding(
            "RG006",
            f"Entry marked deprecated in the registry{suffix}",
            Severity.LOW,
            Confidence.HIGH,
            RULE_OWASP["RG006"],
            "_meta.statusMessage",
            message or "",
            "Prefer the replacement the status message points to, if any.",
        )
    ]


def rg008_packages_agree(entry: Entry) -> RuleResult:
    """RG008: packages of the same registry type name the same package."""
    packages: Sequence[Mapping[str, Any]] = entry["packages"]
    if len(packages) < 2:
        return Skip(SkipReason.NOT_APPLICABLE)
    first_by_type: dict[str, tuple[int, str]] = {}
    for i, p in enumerate(packages):
        key = p["registry_type"]
        ident = p["identifier"].casefold()
        if key not in first_by_type:
            first_by_type[key] = (i, ident)
        elif first_by_type[key][1] != ident:
            return [
                _finding(
                    "RG008",
                    "Entry lists different packages of the same registry type "
                    f"(packages[{first_by_type[key][0]}] and packages[{i}])",
                    Severity.LOW,
                    Confidence.MEDIUM,
                    RULE_OWASP["RG008"],
                    f"server.packages[{i}].identifier",
                    p["identifier"],
                    "Confirm which package is the server before installing.",
                )
            ]
    return []


# --- remote URL rules (parsed as text, never fetched)


AMBIGUOUS_HOST: Final = "(ambiguous host)"


@dataclass(frozen=True)
class _UrlParts:
    scheme: str | None
    userinfo: str
    host: str
    port: str
    # The "@" rule and RFC 3986 disagree on where the host is; host and port are not
    # trusted then (see _split_url).
    ambiguous: bool = False


def _authority_end(rest: str) -> int:
    ends = [i for i in (rest.find("?"), rest.find("#")) if i != -1]
    return min(ends) if ends else len(rest)


def _split_url(url: str) -> _UrlParts:
    """Split without urllib so {placeholders} survive and no part is decoded.

    Userinfo: everything before the last "@" ahead of the query or fragment. That is
    stricter than RFC 3986 (which ends the authority at "/"), so a password containing
    "/" is still treated, and redacted, as a credential.

    Host and port: from the RFC 3986 authority (up to the first "/", "?" or "#"). When the
    two rules disagree ("https://h/a@x" or "https://u:pa/ss@h"), either reading could put
    path or userinfo text in the host slot, so host is AMBIGUOUS_HOST and port is empty.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        return _UrlParts(None, "", "", "")
    head = rest[: _authority_end(rest)]
    at = head.rfind("@")
    userinfo = head[:at] if at != -1 else ""
    authority = head.split("/", 1)[0]
    if at != -1 and "@" not in authority:
        return _UrlParts(scheme, userinfo, AMBIGUOUS_HOST, "", ambiguous=True)
    hostport = authority.rpartition("@")[2]
    if hostport.startswith("["):
        host, _, after = hostport.partition("]")
        host, port = host + "]", after.removeprefix(":")
    elif ":" in hostport:
        host, _, port = hostport.rpartition(":")
    else:
        host, port = hostport, ""
    return _UrlParts(scheme, userinfo, host, port)


REDACTED: Final = "<redacted>"


@dataclass(frozen=True)
class _CredentialHit:
    kind: str  # "userinfo" or "param"
    start: int  # offset in the redacted URL
    placeholder: bool


def _param_key(key: str) -> str:
    """Compare parameter names percent-decoded, without hidden characters, lowercased."""
    return "".join(c for c in unquote(key) if hidden_class(c) is None).lower()


def redact_url(
    url: str, credential_names: frozenset[str]
) -> tuple[str, tuple[_CredentialHit, ...]]:
    """Return the URL with userinfo, credential parameter values and any fragment
    replaced by <redacted>, plus where each credential was. The result is the only form
    of a remote URL that RG009-RG011 put in evidence."""
    scheme, sep, rest = url.partition("://")
    out = f"{scheme}://" if sep else ""
    if not sep:
        rest = url
    split = _authority_end(rest)
    head, tail = rest[:split], rest[split:]
    hits: list[_CredentialHit] = []
    at = head.rfind("@")
    if at != -1:
        hits.append(_CredentialHit("userinfo", len(out), placeholder=False))
        out += f"{REDACTED}@"
        head = head[at + 1 :]
    out += head
    if tail.startswith("?"):
        query, hash_sign, fragment = tail[1:].partition("#")
        out += "?"
        for n, pair in enumerate(query.split("&")):
            if n:
                out += "&"
            key, eq, value = pair.partition("=")
            if eq and value and _param_key(key) in credential_names:
                hits.append(_CredentialHit("param", len(out), _placeholder(value)))
                out += f"{key}={REDACTED}"
            else:
                out += pair
        if hash_sign:
            out += f"#{REDACTED}" if fragment else "#"
    elif tail.startswith("#"):
        out += f"#{REDACTED}" if len(tail) > 1 else "#"
    return out, tuple(hits)


def _placeholder(text: str) -> bool:
    return "{" in text or "}" in text


def _remote(entry: Entry, index: int) -> str:
    return entry["remotes"][index]["url"]


def _names_from(filename: str) -> frozenset[str]:
    names = load_rule_data(filename).get("names")
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise RuleDataError(f"{filename}: names must be a list of strings")
    return frozenset(n.lower() for n in names)


def _credential_names() -> frozenset[str]:
    """The narrow list RG011 flags (data/rg011_credential_params.yaml)."""
    return _names_from("rg011_credential_params.yaml")


def _redact_names() -> frozenset[str]:
    """Everything hidden when a URL is displayed: the flag list plus the broader
    data/url_redact_params.yaml."""
    return _credential_names() | _names_from("url_redact_params.yaml")


def display_url(url: str | None) -> str:
    """A URL as shown in evidence outside RG009-RG011: userinfo, credential-like
    parameter values and the fragment hidden (redact_url with the broad list)."""
    if not url:
        return ""
    return redact_url(url, _redact_names())[0]


_SCHEME_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")
_PORT_RE: Final = re.compile(r"[0-9]{1,5}|\{[A-Za-z0-9_]+\}")


def url_evidence(url: str, params: Sequence[str] = ()) -> str:
    """The only evidence RG009-RG011 show: scheme, host and port, plus the names of the
    flagged parameters. Never the path, query values, userinfo or fragment.

    A "scheme" that is not a URI scheme (it would hold whatever preceded "://") is shown as
    (no scheme), and a "port" that is neither digits nor a {placeholder} as (invalid port),
    so no other part of the URL can reach the output through those slots.
    """
    parts = _split_url(url)
    if parts.scheme is None or not _SCHEME_RE.fullmatch(parts.scheme):
        return _with_params("(no scheme)", params)
    port = parts.port
    if port and not _PORT_RE.fullmatch(port):
        port = "(invalid port)"
    return _with_params(
        f"{parts.scheme}://{parts.host}" + (f":{port}" if port else ""), params
    )


def _with_params(shown: str, params: Sequence[str]) -> str:
    return shown + (" [parameters: " + ", ".join(params) + "]" if params else "")


def _query_pairs(url: str) -> list[tuple[str, str]]:
    rest = url.partition("://")[2] or url
    tail = rest[_authority_end(rest) :]
    if not tail.startswith("?"):
        return []
    query = tail[1:].split("#", 1)[0]
    return [tuple(pair.partition("=")[::2]) for pair in query.split("&") if pair]


def _path_segments(url: str) -> list[str]:
    rest = url.partition("://")[2] or url
    head = rest[: _authority_end(rest)]
    after_userinfo = head[head.rfind("@") + 1 :]
    _, slash, path = after_userinfo.partition("/")
    return [segment for segment in path.split("/") if segment] if slash else []


def rg009_https(entry: Entry, index: int) -> RuleResult:
    """RG009: the remote URL's scheme is literally https."""
    url = _remote(entry, index)
    scheme = _split_url(url).scheme
    if scheme is not None and scheme.lower() == "https":
        return []
    return [
        _finding(
            "RG009",
            "Remote URL does not use https",
            Severity.HIGH,
            Confidence.HIGH,
            RULE_OWASP["RG009"],
            f"server.remotes[{index}].url",
            url_evidence(url),
            "Do not connect over an unencrypted or unknown scheme.",
        )
    ]


def rg010_host_in_namespace(entry: Entry, index: int) -> RuleResult:
    """RG010: domain namespaces only; host is the reversed namespace or a subdomain."""
    namespace = entry["name"].split("/", 1)[0].lower()
    if namespace.startswith(_GITHUB_NAMESPACE):
        return Skip(SkipReason.NOT_APPLICABLE)
    url = _remote(entry, index)
    parts = _split_url(url)
    host = parts.host.lower()
    if not host or parts.ambiguous or _placeholder(host):
        return Skip(SkipReason.NOT_APPLICABLE)
    domain = ".".join(reversed(namespace.split(".")))
    if host == domain or host.endswith("." + domain):
        return []
    return [
        _finding(
            "RG010",
            "Remote URL host is outside the entry's namespace domain",
            Severity.INFO,
            Confidence.LOW,
            RULE_OWASP["RG010"],
            f"server.remotes[{index}].url",
            url_evidence(url),
            "Confirm the host is operated by the namespace owner.",
        )
    ]


_HEADER_ADVICE: Final = (
    "Send credentials in a header, not the URL, where logs and proxies keep them."
)


def rg011_credentials(
    entry: Entry, index: int, credential_names: frozenset[str] | None = None
) -> RuleResult:
    """RG011: userinfo, credential-named query parameters, or values shaped like a known
    credential format (secrets.py) in a query value or path segment. Evidence is scheme,
    host and port plus parameter names; no value is ever shown."""
    names = credential_names or _credential_names()
    url = _remote(entry, index)
    location = f"server.remotes[{index}].url"
    owasp = RULE_OWASP["RG011 credentials"]
    findings = []

    def add(
        title: str,
        severity: Severity,
        confidence: Confidence,
        params=(),
        advice=_HEADER_ADVICE,
    ):
        findings.append(
            _finding(
                "RG011",
                title,
                severity,
                confidence,
                owasp,
                location,
                url_evidence(url, params),
                advice,
            )
        )

    if _split_url(url).userinfo:
        add(
            "Remote URL embeds credentials (userinfo)",
            Severity.HIGH,
            Confidence.HIGH,
            advice="Remove credentials from the URL; anyone who sees the URL has them.",
        )
    literal, placeholder, by_name = [], [], set()
    for key, value in _query_pairs(url):
        if value and _param_key(key) in names:
            (placeholder if _placeholder(value) else literal).append(key)
            by_name.add(key)
    if literal:
        add(
            "Remote URL embeds a credential parameter",
            Severity.HIGH,
            Confidence.MEDIUM,
            literal,
        )
    if placeholder:
        add(
            "Remote URL carries a credential parameter (filled in at install time)",
            Severity.LOW,
            Confidence.MEDIUM,
            placeholder,
        )
    for key, value in _query_pairs(url):
        if key in by_name or _placeholder(value):
            continue
        for hit in find_secrets(unquote(value))[:1]:
            add(
                f"Remote URL query value matches the documented {hit.kind} format",
                Severity.HIGH,
                Confidence.MEDIUM,
                [key],
            )
    for n, segment in enumerate(_path_segments(url)):
        if _placeholder(segment):
            continue
        for hit in find_secrets(unquote(segment))[:1]:
            add(
                f"Remote URL path segment {n} matches the documented {hit.kind} format",
                Severity.HIGH,
                Confidence.MEDIUM,
            )
    return findings


def rg011_port(entry: Entry, index: int) -> RuleResult:
    """RG011: an explicit literal port other than 443."""
    url = _remote(entry, index)
    port = _split_url(url).port
    if not port or port == "443":
        return []
    if _placeholder(port):
        return Skip(SkipReason.NOT_APPLICABLE)
    return [
        _finding(
            "RG011",
            "Remote URL uses an unusual port",
            Severity.LOW,
            Confidence.MEDIUM,
            RULE_OWASP["RG011 port"],
            f"server.remotes[{index}].url",
            url_evidence(url),
            "Confirm the port is expected for this service.",
        )
    ]
