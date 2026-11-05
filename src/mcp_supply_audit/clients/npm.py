"""npm registry client: one version document (docs/api-notes.md, "npm").

Returns a normalized dict holding only what the RG and PK rules need. A field the PK rules
read that is malformed is None, so only the rule that needs it is skipped. Raises only the
typed errors from clients/_http.py (ShapeMismatch included). All text in the result is
target-controlled. Install-script commands are never kept, only their names.
"""

from typing import Any, Final

from mcp_supply_audit.clients._http import Host, HttpClient, ShapeMismatch

# 404 bodies are bare JSON strings (api-notes, "Version documents: missing versions").
_PACKAGE_NOT_FOUND: Final = "Not Found"
_VERSION_NOT_FOUND_PREFIX: Final = "version not found: "
# The install-time lifecycle hooks (api-notes, "Version document").
INSTALL_HOOKS: Final = ("preinstall", "install", "postinstall")


def _install_scripts(data: dict[str, Any]) -> tuple[str, ...] | None:
    """Names of the install hooks present, in INSTALL_HOOKS order, or None if `scripts` is
    malformed. The command text is dropped here."""
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return None
    return tuple(hook for hook in INSTALL_HOOKS if hook in scripts)


def _has_provenance(data: dict[str, Any]) -> bool | None:
    """Whether dist.attestations names a provenance predicateType, or None if `dist` is
    malformed. No `attestations` key means none (api-notes, "Provenance")."""
    dist = data.get("dist")
    if not isinstance(dist, dict):
        return None
    attestations = dist.get("attestations")
    if attestations is None:
        return False
    if not isinstance(attestations, dict):
        return None
    provenance = attestations.get("provenance")
    predicate = (
        provenance.get("predicateType") if isinstance(provenance, dict) else None
    )
    return isinstance(predicate, str) and bool(predicate)


def parse_version_doc(data: Any) -> dict[str, Any]:
    """Normalize a /{package}/{version} body. Raises ShapeMismatch."""
    if not isinstance(data, dict):
        raise ShapeMismatch("npm version document is not an object.")
    repository = data.get("repository")
    if isinstance(repository, dict):
        repository_url = repository.get("url")
    else:
        repository_url = repository  # npm also allows a plain string
    mcp_name = data.get("mcpName")
    version = data.get("version")
    deprecated = data.get("deprecated")
    return {
        "package_exists": True,
        "version_exists": True,
        "repository_urls": (repository_url,) if isinstance(repository_url, str) else (),
        "mcp_name": mcp_name if isinstance(mcp_name, str) else None,
        "mcp_name_present": "mcpName" in data,
        "version": version if isinstance(version, str) else None,
        "deprecated": deprecated if isinstance(deprecated, str) else None,
        "deprecated_present": "deprecated" in data,
        "install_scripts": _install_scripts(data),
        "has_provenance": _has_provenance(data),
    }


async def get_version(http: HttpClient, package: str, version: str) -> dict[str, Any]:
    """Fetch one version document. `package` and `version` must already be validated."""
    response = await http.get(
        Host.NPM, "/{package}/{version}", {"package": package, "version": version}
    )
    if response.status == 200:
        return parse_version_doc(response.json())
    if response.status != 404:
        raise ShapeMismatch(f"npm registry answered HTTP {response.status}.")
    body = response.json()
    if body == _PACKAGE_NOT_FOUND:
        package_exists = False
    elif isinstance(body, str) and body.startswith(_VERSION_NOT_FOUND_PREFIX):
        package_exists = True
    else:
        raise ShapeMismatch("npm registry sent an unrecognized 404 body.")
    return {
        "package_exists": package_exists,
        "version_exists": False,
        "repository_urls": (),
        "mcp_name": None,
        "mcp_name_present": False,
        "version": None,
        "deprecated": None,
        "deprecated_present": False,
        "install_scripts": None,
        "has_provenance": None,
    }
