"""RG001-RG011: registry-entry rules. Rules live in docs/rules-registry.md; read it first.

v0.1 has only the RG001 URL normalizer; the rules and their clients are not written yet.
"""

from typing import Final
from urllib.parse import urlsplit, urlunsplit

_MAX_URL_LEN: Final = 2048


def normalize_repo_url(url: object) -> str | None:
    """Return a declared repository URL in comparable form, or None if it is not a URL.

    Strips a leading "git+", any trailing "/" and ".git" (in either order), lowercases the
    host, and drops a leading "www.". Scheme, userinfo, port, path case, query and fragment
    are kept as given. Parses the string only; never resolves or fetches it.
    """
    if not isinstance(url, str) or len(url) > _MAX_URL_LEN:
        return None
    text = url.strip()
    text = text.removeprefix("git+")
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None  # e.g. "github:owner/repo" or "git@github.com:owner/repo.git"

    userinfo, at, hostport = parts.netloc.rpartition("@")
    if hostport.startswith("["):  # IPv6 literal: host and port split at "]"
        host, _, rest = hostport.partition("]")
        host, port = host + "]", rest
    else:
        host, sep, port = hostport.partition(":")
        port = sep + port
    host = host.lower().removeprefix("www.")
    if not host or host == "[]":
        return None

    path = parts.path
    while path.endswith(("/", ".git")):
        path = path.removesuffix("/").removesuffix(".git")
    return urlunsplit(
        (parts.scheme, f"{userinfo}{at}{host}{port}", path, parts.query, parts.fragment)
    )
