"""PyPI client: one release's metadata, the latest version, and per-file provenance
(docs/api-notes.md, "PyPI" and "audit_package data").

Returns normalized dicts holding only what the RG and PK rules need. A field the PK rules
read that is missing or malformed is None, so only the rule that needs it is skipped. Raises
only the typed errors from clients/_http.py (ShapeMismatch included). All text in the result
is target-controlled.
"""

from typing import Any, Final

from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients._http import Accept, Host, HttpClient, ShapeMismatch
from mcp_supply_audit.validation import validate_version

# JSON 404 body for a file without provenance; an unknown filename gets an HTML 404 instead.
_NO_PROVENANCE_PREFIX: Final = "No provenance available for "


def _files(urls: list[Any]) -> tuple[tuple[str, str | None], ...] | None:
    """(filename, upload_time_iso_8601) per file, or None if any entry is malformed."""
    files = []
    for f in urls:
        if not isinstance(f, dict) or not isinstance(f.get("filename"), str):
            return None
        uploaded = f.get("upload_time_iso_8601")
        files.append((f["filename"], uploaded if isinstance(uploaded, str) else None))
    return tuple(files)


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def parse_release(data: Any) -> dict[str, Any]:
    """Normalize a /pypi/{project}/{version}/json body. Raises ShapeMismatch."""
    if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
        raise ShapeMismatch("PyPI release has no info object.")
    info = data["info"]
    urls = data.get("urls")
    if not isinstance(urls, list):
        raise ShapeMismatch("PyPI release has no urls list.")
    project_urls = info.get("project_urls") or {}
    if not isinstance(project_urls, dict):
        raise ShapeMismatch("PyPI release has malformed project_urls.")
    description = info.get("description")
    if description is not None and not isinstance(description, str):
        raise ShapeMismatch("PyPI release has a non-string description.")
    return {
        "package_exists": True,
        "version_exists": True,
        "file_count": len(urls),
        # Labels are free-form (api-notes), so every string value is a candidate.
        "repository_urls": tuple(
            v for v in project_urls.values() if isinstance(v, str)
        ),
        "description": description,
        "yanked": info.get("yanked") if isinstance(info.get("yanked"), bool) else None,
        "yanked_reason": _str_or_none(info.get("yanked_reason")),
        "files": _files(urls),
        "home_page": _str_or_none(info.get("home_page")),
    }


def _missing(package_exists: bool) -> dict[str, Any]:
    return {
        "package_exists": package_exists,
        "version_exists": False,
        "file_count": None,
        "repository_urls": (),
        "description": None,
        "yanked": None,
        "yanked_reason": None,
        "files": None,
        "home_page": None,
    }


async def get_release(http: HttpClient, project: str, version: str) -> dict[str, Any]:
    """Fetch one release. A 404 there is ambiguous, so the project endpoint's status
    (body not read) decides between a missing project and a missing version.

    `project` and `version` must already be validated.
    """
    response = await http.get(
        Host.PYPI,
        "/pypi/{project}/{version}/json",
        {"project": project, "version": version},
    )
    if response.status == 200:
        return parse_release(response.json())
    if response.status != 404:
        raise ShapeMismatch(f"PyPI answered HTTP {response.status}.")
    project_status = await http.get(
        Host.PYPI, "/pypi/{project}/json", {"project": project}, status_only=True
    )
    if project_status.status == 404:
        return _missing(package_exists=False)
    if project_status.status == 200:
        return _missing(package_exists=True)
    raise ShapeMismatch(f"PyPI answered HTTP {project_status.status}.")


async def get_latest_version(http: HttpClient, project: str) -> str | None:
    """`info.version` from the project JSON, or None if the project does not exist.

    The project JSON is the only JSON source of the latest version and exceeds the PyPI cap
    for large projects (api-notes, "Resolving the latest version"): ResponseTooLarge then.
    A version that would not pass validate_version unchanged is ShapeMismatch.
    """
    response = await http.get(Host.PYPI, "/pypi/{project}/json", {"project": project})
    if response.status == 404:
        return None
    if response.status != 200:
        raise ShapeMismatch(f"PyPI answered HTTP {response.status}.")
    data = response.json()
    info = data.get("info") if isinstance(data, dict) else None
    version = info.get("version") if isinstance(info, dict) else None
    try:
        if validate_version(version) != version:
            raise ShapeMismatch("PyPI project JSON has a malformed version.")
    except ToolError:
        raise ShapeMismatch("PyPI project JSON has a malformed version.") from None
    return version


async def file_has_provenance(
    http: HttpClient, project: str, version: str, filename: str
) -> bool:
    """Whether one file of a release has a provenance bundle.

    True on a 200 with a non-empty `attestation_bundles`; False on the JSON 404 "No
    provenance available for ..."; anything else (an HTML 404 for an unknown file, another
    status, another shape) is ShapeMismatch. `filename` comes from the release JSON and is
    sent as one encoded path segment.
    """
    try:
        response = await http.get(
            Host.PYPI,
            "/integrity/{project}/{version}/{filename}/provenance",
            {"project": project, "version": version, "filename": filename},
            accept=Accept.PYPI_INTEGRITY,
        )
    except ValueError:  # build_path refused the filename ("..", empty, too long)
        raise ShapeMismatch("PyPI release lists an unusable filename.") from None
    if response.status == 404:
        body = response.json()
        message = body.get("message") if isinstance(body, dict) else None
        if isinstance(message, str) and message.startswith(_NO_PROVENANCE_PREFIX):
            return False
        raise ShapeMismatch("PyPI sent an unrecognized provenance 404.")
    if response.status != 200:
        raise ShapeMismatch(f"PyPI answered HTTP {response.status}.")
    body = response.json()
    bundles = body.get("attestation_bundles") if isinstance(body, dict) else None
    if not isinstance(bundles, list):
        raise ShapeMismatch("PyPI provenance has no attestation_bundles list.")
    return bool(bundles)
