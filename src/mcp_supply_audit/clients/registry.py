"""MCP Registry client: one entry's latest version (docs/api-notes.md, "MCP Registry").

Returns a normalized dict holding only what the RG rules need. Raises only the typed errors
from clients/_http.py (ShapeMismatch included). All text in the result is target-controlled.
"""

from typing import Any, Final

from mcp_supply_audit.clients._http import Host, HttpClient, Query, ShapeMismatch

OFFICIAL_META_KEY: Final = "io.modelcontextprotocol.registry/official"
# Where status lives: nested under OFFICIAL_META_KEY (observed), or directly in _meta
# (the shape official-registry-requirements.md shows). None when neither matches.
META_NESTED: Final = "nested"
META_DOCUMENTED: Final = "documented"


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ShapeMismatch("MCP Registry entry has a non-string field.")
    return value


def _status(meta: Any) -> tuple[str | None, str | None, str | None]:
    """Return (status, status_message, meta_shape), tolerating the documented shape."""
    if not isinstance(meta, dict):
        return None, None, None
    nested = meta.get(OFFICIAL_META_KEY)
    for source, shape in ((nested, META_NESTED), (meta, META_DOCUMENTED)):
        if isinstance(source, dict) and isinstance(source.get("status"), str):
            message = source.get("statusMessage")
            return (
                source["status"],
                message if isinstance(message, str) else None,
                shape,
            )
    return None, None, None


def parse_entry(data: Any) -> dict[str, Any]:
    """Normalize a /versions/latest body. Raises ShapeMismatch."""
    if not isinstance(data, dict) or not isinstance(data.get("server"), dict):
        raise ShapeMismatch("MCP Registry entry has no server object.")
    server = data["server"]
    name, version = server.get("name"), server.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ShapeMismatch("MCP Registry entry has no name or version.")

    repository = server.get("repository")
    if repository is not None and not isinstance(repository, dict):
        raise ShapeMismatch("MCP Registry entry has a malformed repository.")

    packages = server.get("packages") or []
    remotes = server.get("remotes") or []
    if not isinstance(packages, list) or not isinstance(remotes, list):
        raise ShapeMismatch("MCP Registry entry has malformed packages or remotes.")
    norm_packages = []
    for p in packages:
        if not isinstance(p, dict) or not all(
            isinstance(p.get(k), str) for k in ("registryType", "identifier")
        ):
            raise ShapeMismatch("MCP Registry entry has a malformed package.")
        norm_packages.append(
            {
                "registry_type": p["registryType"],
                "identifier": p["identifier"],
                "version": _opt_str(p.get("version")),
                "file_sha256": _opt_str(p.get("fileSha256")),
                "registry_base_url": _opt_str(p.get("registryBaseUrl")),
            }
        )
    norm_remotes = []
    for r in remotes:
        if not isinstance(r, dict) or not isinstance(r.get("url"), str):
            raise ShapeMismatch("MCP Registry entry has a malformed remote.")
        variables = r.get("variables")
        norm_remotes.append(
            {
                "type": _opt_str(r.get("type")),
                "url": r["url"],
                "variables": tuple(variables) if isinstance(variables, dict) else (),
            }
        )

    status, status_message, meta_shape = _status(data.get("_meta"))
    return {
        "name": name,
        "version": version,
        "repository_url": _opt_str((repository or {}).get("url")),
        "packages": norm_packages,
        "remotes": norm_remotes,
        "status": status,
        "status_message": status_message,
        "meta_shape": meta_shape,
    }


async def get_latest_entry(http: HttpClient, name: str) -> dict[str, Any] | None:
    """Fetch an entry's latest version, deleted entries included. None if there is none.

    `name` must already be validated (validation.validate_registry_name).
    """
    response = await http.get(
        Host.REGISTRY,
        "/v0/servers/{name}/versions/latest",
        {"name": name},
        query=Query.INCLUDE_DELETED,
    )
    if response.status == 404:
        return None
    if response.status != 200:
        raise ShapeMismatch(f"MCP Registry answered HTTP {response.status}.")
    entry = parse_entry(response.json())
    # The registry's lookup is case-sensitive (api-notes), so the name must match exactly.
    if entry["name"] != name:
        raise ShapeMismatch("MCP Registry returned a different server than requested.")
    return entry
