"""Input validation for tool arguments. Errors never echo the raw input back."""

import json
import re
from typing import Any, Final

from fastmcp.exceptions import ToolError

# Explicit [A-Za-z0-9] classes throughout: \w and \d match non-ASCII lookalikes.

# PEP 508 project names. PyPI sets no length limit; this cap is ours.
_PYPI_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_MAX_PYPI_NAME_LEN: Final = 200

# npm: optional lowercase @scope/, URL-safe characters, no leading "." or "_". Uppercase is
# accepted in the name because legacy packages (e.g. ZqvexStream) still use it.
_NPM_NAME_RE = re.compile(
    r"(?:@[a-z0-9~-][a-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*"
)
_MAX_NPM_NAME_LEN: Final = 214
_NPM_RESERVED: Final = frozenset({"node_modules", "favicon.ico"})

# The registry schema's name pattern and length limits (OpenAPI ServerJSON.name, recorded in
# docs/api-notes.md): reverse-DNS namespace, one slash, server name.
_REGISTRY_NAME_RE = re.compile(r"([a-zA-Z0-9.-]+)/([a-zA-Z0-9._-]+)")
_MIN_REGISTRY_NAME_LEN: Final = 3
_MAX_REGISTRY_NAME_LEN: Final = 200

# Registry search matches server names, so terms use the name alphabet. The registry
# rejects terms shorter than 3 characters after trimming with a 422.
_SEARCH_TERM_RE = re.compile(r"[a-zA-Z0-9._/-]+")
MIN_SEARCH_TERM_LEN: Final = 3
_MAX_SEARCH_TERM_LEN: Final = _MAX_REGISTRY_NAME_LEN

MAX_TOOLS_LIST_BYTES: Final = 1_048_576
MAX_JSON_DEPTH: Final = 64
# A JSON string literal, or a bracket. Brackets inside strings are not nesting.
_JSON_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]', re.DOTALL)


def validate_pypi_name(name: object) -> str:
    """Return a stripped PyPI project name, or raise ToolError."""
    if isinstance(name, str) and len(name) <= _MAX_PYPI_NAME_LEN:
        candidate = name.strip()
        if candidate.isascii() and _PYPI_NAME_RE.fullmatch(candidate):
            return candidate
    raise ToolError(
        f"Invalid PyPI package name. Expected letters, digits, '.', '_' or '-', up to "
        f"{_MAX_PYPI_NAME_LEN} characters, starting and ending with a letter or digit."
    )


def validate_npm_name(name: object) -> str:
    """Return a stripped npm package name (optionally @scope/name), or raise ToolError."""
    if isinstance(name, str) and len(name) <= _MAX_NPM_NAME_LEN:
        candidate = name.strip()
        if (
            candidate.isascii()
            and _NPM_NAME_RE.fullmatch(candidate)
            and candidate.lower() not in _NPM_RESERVED
        ):
            return candidate
    raise ToolError(
        f"Invalid npm package name. Expected name or @scope/name using URL-safe "
        f"characters, up to {_MAX_NPM_NAME_LEN} characters, not starting with '.' or '_'."
    )


def validate_registry_name(name: object) -> str:
    """Return a stripped MCP registry server name (e.g.
    io.github.zqvex-owner/zqvex-server or com.example/zqvex-server), or raise ToolError.

    Stricter than the schema in one way: neither part may be only dots, and the namespace
    may not have empty labels, so a name can never act as "." or ".." in a URL path.
    """
    if isinstance(name, str) and len(name) <= _MAX_REGISTRY_NAME_LEN:
        candidate = name.strip()
        match = (
            _REGISTRY_NAME_RE.fullmatch(candidate)
            if candidate.isascii() and len(candidate) >= _MIN_REGISTRY_NAME_LEN
            else None
        )
        if match:
            namespace, server = match.groups()
            if server.strip(".") and all(namespace.split(".")):
                return candidate
    raise ToolError(
        "Invalid registry name. Expected <namespace>/<name> using letters, digits, '.', '-' "
        f"(and '_' in the name), up to {_MAX_REGISTRY_NAME_LEN} characters, "
        "e.g. io.github.zqvex-owner/zqvex-server."
    )


def validate_search_term(term: object) -> str:
    """Return a stripped registry search term, or raise ToolError."""
    if isinstance(term, str) and len(term) <= _MAX_SEARCH_TERM_LEN:
        candidate = term.strip()
        if (
            len(candidate) >= MIN_SEARCH_TERM_LEN
            and candidate.isascii()
            and _SEARCH_TERM_RE.fullmatch(candidate)
            # Punctuation alone ("../..") matches nothing useful in a name search.
            and any(c.isalnum() for c in candidate)
        ):
            return candidate
    raise ToolError(
        f"Invalid search term. Expected {MIN_SEARCH_TERM_LEN} to {_MAX_SEARCH_TERM_LEN} "
        "characters of a server name (letters, digits, '.', '_', '-', '/'), "
        "including at least one letter or digit."
    )


# Versions: semver with pre-release/build (1.0.0-rc.1+b2), PEP 440 (2!1.0.post1), tags.
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~!-]*")
_MAX_VERSION_LEN: Final = 128

# Schema-level caps for tool arguments (server.py): the validators above enforce the exact
# per-ecosystem limits, so these only bound what reaches them.
MAX_NAME_LEN: Final = max(_MAX_PYPI_NAME_LEN, _MAX_NPM_NAME_LEN, _MAX_REGISTRY_NAME_LEN)
MAX_VERSION_LEN: Final = _MAX_VERSION_LEN


def validate_version(value: object) -> str:
    """Return a stripped package version, or raise ToolError."""
    if isinstance(value, str) and len(value) <= _MAX_VERSION_LEN:
        candidate = value.strip()
        if candidate.isascii() and _VERSION_RE.fullmatch(candidate):
            return candidate
    raise ToolError(
        f"Invalid version. Expected a version string up to {_MAX_VERSION_LEN} characters, "
        "e.g. 2.14.1, 1.0.0-rc.1, or 2!1.0.post1."
    )


def text_depth_exceeds(text: str, limit: int) -> bool:
    """True if JSON text nests brackets deeper than limit (strings are skipped)."""
    depth = 0
    for match in _JSON_TOKEN_RE.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > limit:
                return True
        elif token in ("]", "}"):
            depth -= 1
    return False


def _object_depth_exceeds(obj: dict[str, Any] | list[Any], limit: int) -> bool:
    # Iterative, so a deep (or cyclic) object cannot hit the recursion limit.
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        for child in node.values() if isinstance(node, dict) else node:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return False


_TOO_LARGE = (
    f"tools/list snapshot is too large (max {MAX_TOOLS_LIST_BYTES // 1024} KiB)."
)
_TOO_DEEP = f"tools/list snapshot is nested too deeply (max depth {MAX_JSON_DEPTH})."
_NOT_JSON = "tools/list snapshot is not valid JSON."
TOOLS_LIST_NOT_JSON: Final = _NOT_JSON
TOOLS_LIST_NOT_CONTAINER: Final = "tools/list snapshot must be a JSON object or array."
_NOT_TEXT = "tools_snapshot must be JSON text, not an object."


def tools_list_text_bytes(snapshot: object) -> bytes:
    """Return a tools/list snapshot given as JSON text as UTF-8 bytes for safe_json, or
    raise ToolError. Only text is accepted. Size and nesting depth are checked before
    anything is parsed."""
    if not isinstance(snapshot, str):
        raise ToolError(_NOT_TEXT)
    # A str never has more characters than UTF-8 bytes, so huge input is rejected
    # before it is encoded.
    if len(snapshot) > MAX_TOOLS_LIST_BYTES:
        raise ToolError(_TOO_LARGE)
    encoded = snapshot.encode("utf-8", "surrogatepass")
    if len(encoded) > MAX_TOOLS_LIST_BYTES:
        raise ToolError(_TOO_LARGE)
    if text_depth_exceeds(snapshot, MAX_JSON_DEPTH):
        raise ToolError(_TOO_DEEP)
    return encoded


def validate_tools_list_json(snapshot: object) -> dict[str, Any] | list[Any]:
    """Return a parsed tools/list snapshot (JSON text, object, or array), or raise ToolError.

    Size and nesting depth are checked before parsing or serializing, so hostile input
    cannot exhaust memory or hit the recursion limit.
    """
    if isinstance(snapshot, str):
        # A str never has more characters than UTF-8 bytes, so huge input is rejected
        # before it is encoded.
        if (
            len(snapshot) > MAX_TOOLS_LIST_BYTES
            or len(snapshot.encode("utf-8", "surrogatepass")) > MAX_TOOLS_LIST_BYTES
        ):
            raise ToolError(_TOO_LARGE)
        if text_depth_exceeds(snapshot, MAX_JSON_DEPTH):
            raise ToolError(_TOO_DEEP)
        try:
            parsed = json.loads(snapshot)
        except ValueError:
            raise ToolError(_NOT_JSON) from None
    elif isinstance(snapshot, (dict, list)):
        if _object_depth_exceeds(snapshot, MAX_JSON_DEPTH):
            raise ToolError(_TOO_DEEP)
        try:
            encoded = json.dumps(snapshot, ensure_ascii=False).encode(
                "utf-8", "surrogatepass"
            )
        except (TypeError, ValueError):
            raise ToolError(_NOT_JSON) from None
        if len(encoded) > MAX_TOOLS_LIST_BYTES:
            raise ToolError(_TOO_LARGE)
        parsed = snapshot
    else:
        raise ToolError(
            "tools/list snapshot must be JSON text, an object, or an array."
        )

    if not isinstance(parsed, (dict, list)):
        raise ToolError(TOOLS_LIST_NOT_CONTAINER)
    return parsed
