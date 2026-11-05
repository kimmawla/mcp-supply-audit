"""Build src/mcp_supply_audit/data/reference_names.json for check_typosquat.

Dev-only: run by hand when the reference names are refreshed. Never imported by src/ (a test
checks). Reads scripts/curated_names.yaml, refusing any entry without a source_url, and with
--crawl also lists server names from the MCP Registry. The crawl sends GET requests to the
registry host only, follows only cursors the server returned, uses a fixed page size and
page cap, waits 1 s between requests, keeps names only (never descriptions), and skips any
name that fails validate_registry_name. It stops when the server returns no next cursor, at
the page cap (the file records partial: true), at the time limit, or when the server repeats a
cursor (for either of the last two, nothing is written and an existing file is left as is).
Crawled names are tagged listed-not-curated and feed only the registry ecosystem
(docs/rules-typosquat.md). Progress goes to stderr, one flushed line per page.

Usage: uv run scripts/build_reference_names.py [--crawl] [--max-pages N]
       [--time-limit-minutes M]
Exit status: 0 written, 1 curated list refused, 2 crawl failed (nothing written),
3 time limit reached (nothing written), 4 server repeated a cursor (nothing written).
"""

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients._http import ShapeMismatch, safe_json
from mcp_supply_audit.validation import (
    validate_npm_name,
    validate_pypi_name,
    validate_registry_name,
)

ROOT = Path(__file__).resolve().parents[1]
CURATED = ROOT / "scripts/curated_names.yaml"
OUTPUT = ROOT / "src/mcp_supply_audit/data/reference_names.json"

REGISTRY_HOST = "registry.modelcontextprotocol.io"
REGISTRY_LIST_URL = f"https://{REGISTRY_HOST}/v0/servers"
CRAWL_SOURCE = "mcp-registry-crawl"
PAGE_SIZE = 100  # the registry's maximum (docs/api-notes.md)
MAX_PAGES = 100  # a 55-page crawl at limit=100 covered the registry (docs/api-notes.md)
DELAY_SECONDS = 1.0
TIME_LIMIT_MINUTES = 20.0
MAX_PAGE_BYTES = 1024 * 1024  # largest page measured: 190 KB at limit=100

VALIDATORS = {
    "pypi": validate_pypi_name,
    "npm": validate_npm_name,
    "registry": validate_registry_name,
}
CURATED_TYPES = frozenset({"reference-server", "dependency"})
LISTED_TYPE = "listed-not-curated"

STOP_NO_CURSOR = "the server returned no next cursor"
STOP_PAGE_CAP = "the page cap was reached; the list is partial"
STOP_REPEATED_CURSOR = "the server repeated a cursor"


class CurationError(ValueError):
    """The curated list has entries the script refuses."""


class CrawlTimeLimit(Exception):
    """The crawl reached its total time limit before finishing."""

    def __init__(self, pages_fetched: int) -> None:
        super().__init__(pages_fetched)
        self.pages_fetched = pages_fetched


class CrawlRepeatedCursor(Exception):
    """The server returned a cursor it had already returned, so the listing cannot be trusted."""

    def __init__(self, pages_fetched: int) -> None:
        super().__init__(pages_fetched)
        self.pages_fetched = pages_fetched


def log(message: str) -> None:
    # stderr only, flushed per line, so progress shows while the crawl runs.
    print(message, file=sys.stderr, flush=True)


def load_curated(text: str) -> list[dict[str, str]]:
    """Validated curated entries. Raises CurationError listing every refused entry."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or data.get("version") != 1:
        raise CurationError("curated list: expected a mapping with version: 1")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise CurationError("curated list: entries must be a non-empty list")
    problems: list[str] = []
    result: list[dict[str, str]] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"entries[{i}]: not a mapping")
            continue
        url = entry.get("source_url")
        if not isinstance(url, str) or not url.startswith("https://"):
            problems.append(f"entries[{i}]: no https source_url")
            continue
        name, ecosystem = entry.get("name"), entry.get("ecosystem")
        if ecosystem not in VALIDATORS:
            problems.append(f"entries[{i}]: ecosystem must be pypi, npm or registry")
            continue
        try:
            valid = VALIDATORS[ecosystem](name)
        except ToolError:
            valid = None
        if valid != name:
            problems.append(f"entries[{i}]: name fails {ecosystem} validation")
            continue
        if entry.get("source_type") not in CURATED_TYPES:
            problems.append(
                f"entries[{i}]: source_type must be one of {sorted(CURATED_TYPES)}"
            )
            continue
        checked_at = entry.get("checked_at")
        try:
            date.fromisoformat(checked_at)
        except (TypeError, ValueError):
            problems.append(f"entries[{i}]: checked_at must be a quoted ISO date")
            continue
        result.append(
            {
                "name": name,
                "ecosystem": ecosystem,
                "source_type": entry["source_type"],
                "source_url": url,
                "checked_at": checked_at,
            }
        )
    if problems:
        raise CurationError("\n".join(problems))
    return result


@dataclass(frozen=True)
class CrawlResult:
    names: list[str]  # valid, unique, sorted
    invalid: int
    pages_fetched: int
    page_cap: int
    stop_reason: str

    @property
    def partial(self) -> bool:
        return self.stop_reason == STOP_PAGE_CAP


def crawl(
    fetch_page: Callable[[dict[str, str]], bytes],
    *,
    max_pages: int = MAX_PAGES,
    time_limit_seconds: float = TIME_LIMIT_MINUTES * 60,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> CrawlResult:
    """List registry server names, logging progress to stderr.

    fetch_page gets the query parameters and returns the body. Only a nextCursor the server
    returned is sent back. Raises CrawlTimeLimit when the time limit is reached before the
    next request, and CrawlRepeatedCursor when the server repeats a cursor.
    """
    log(
        f"crawl: page cap {MAX_PAGES} (default), --max-pages {max_pages}, "
        f"page size {PAGE_SIZE}, delay {DELAY_SECONDS:g} s, "
        f"time limit {time_limit_seconds / 60:g} min"
    )
    started = clock()
    names: set[str] = set()
    invalid = 0
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for page in range(max_pages):
        if page:
            sleep(DELAY_SECONDS)
        if clock() - started >= time_limit_seconds:
            raise CrawlTimeLimit(page)
        params = {"limit": str(PAGE_SIZE), "version": "latest"}
        if cursor is not None:
            params["cursor"] = cursor
        requested = clock()
        body = fetch_page(params)
        request_seconds = clock() - requested
        data: Any = safe_json(body)
        if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
            raise ShapeMismatch("registry page has no servers list")
        for item in data["servers"]:
            server = item.get("server") if isinstance(item, dict) else None
            name = server.get("name") if isinstance(server, dict) else None
            try:
                valid = validate_registry_name(name)
            except ToolError:
                valid = None
            if valid is None or valid != name:
                invalid += 1
            else:
                names.add(valid)
        log(
            f"crawl: page {page + 1}: {len(names)} names so far, "
            f"request {request_seconds:.2f} s, elapsed {clock() - started:.1f} s"
        )
        metadata = data.get("metadata")
        cursor = metadata.get("nextCursor") if isinstance(metadata, dict) else None
        if not isinstance(cursor, str) or not cursor:
            stop_reason = STOP_NO_CURSOR
            break
        if cursor in seen_cursors:
            raise CrawlRepeatedCursor(page + 1)
        seen_cursors.add(cursor)
    else:
        stop_reason = STOP_PAGE_CAP
    return CrawlResult(
        names=sorted(names),
        invalid=invalid,
        pages_fetched=page + 1,
        page_cap=max_pages,
        stop_reason=stop_reason,
    )


def http_fetch_page(client: httpx.Client) -> Callable[[dict[str, str]], bytes]:
    def fetch(params: dict[str, str]) -> bytes:
        response = client.get(REGISTRY_LIST_URL, params=params)
        if response.url.host != REGISTRY_HOST or response.status_code != 200:
            raise httpx.HTTPStatusError(
                f"registry answered HTTP {response.status_code}",
                request=response.request,
                response=response,
            )
        if len(response.content) > MAX_PAGE_BYTES:
            raise ShapeMismatch("registry page exceeds the size cap")
        return response.content

    return fetch


def build_document(
    curated: list[dict[str, str]], crawled: CrawlResult | None, today: date
) -> dict[str, Any]:
    """The compact reference file: a sources table, curated entries as objects, and crawled
    names as one sorted list per ecosystem with the source and crawl limits recorded once."""
    sources = {
        f"{e['source_type']}/{e['name']}": {
            "id": f"{e['source_type']}/{e['name']}",
            "name": e["name"],
            "type": e["source_type"],
            "url": e["source_url"],
        }
        for e in curated
    }
    entries = [
        {
            "checked_at": e["checked_at"],
            "ecosystem": e["ecosystem"],
            "name": e["name"],
            "source": f"{e['source_type']}/{e['name']}",
        }
        for e in curated
    ]
    listed: dict[str, Any] = {}
    curated_registry = {e["name"] for e in curated if e["ecosystem"] == "registry"}
    if crawled is not None and crawled.names:
        sources[CRAWL_SOURCE] = {
            "id": CRAWL_SOURCE,
            "name": "MCP Registry server list",
            "type": LISTED_TYPE,
            "url": REGISTRY_LIST_URL,
        }
        listed["registry"] = {
            "names": sorted(set(crawled.names) - curated_registry),
            "page_cap": crawled.page_cap,
            "page_size": PAGE_SIZE,
            "pages_fetched": crawled.pages_fetched,
            "partial": crawled.partial,
            "source": CRAWL_SOURCE,
        }
    return {
        "curated": sorted(entries, key=lambda e: (e["ecosystem"], e["name"])),
        "generated_at": today.isoformat(),
        "listed": listed,
        "sources": [sources[k] for k in sorted(sources)],
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _positive(kind: type[int] | type[float]) -> Callable[[str], int | float]:
    def parse(text: str) -> int | float:
        value = kind(text)
        if value <= 0:
            raise argparse.ArgumentTypeError("must be positive")
        return value

    return parse


def main(
    argv: list[str] | None = None,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--crawl", action="store_true", help="also list MCP Registry server names"
    )
    parser.add_argument(
        "--max-pages",
        type=_positive(int),
        default=MAX_PAGES,
        help=f"page cap for the crawl (default {MAX_PAGES})",
    )
    parser.add_argument(
        "--time-limit-minutes",
        type=_positive(float),
        default=TIME_LIMIT_MINUTES,
        help=f"total time limit for the crawl (default {TIME_LIMIT_MINUTES:g})",
    )
    args = parser.parse_args(argv)
    try:
        curated = load_curated(CURATED.read_text(encoding="utf-8"))
    except CurationError as exc:
        log(f"refused {CURATED}:\n{exc}")
        return 1

    crawled: CrawlResult | None = None
    if args.crawl:
        with httpx.Client(
            timeout=httpx.Timeout(8.0, connect=3.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            try:
                crawled = crawl(
                    http_fetch_page(client),
                    max_pages=args.max_pages,
                    time_limit_seconds=args.time_limit_minutes * 60,
                    sleep=sleep,
                    clock=clock,
                )
            except CrawlTimeLimit as exc:
                log(
                    f"crawl stopped: the {args.time_limit_minutes:g}-minute time limit "
                    f"was reached after {exc.pages_fetched} pages; nothing written"
                )
                return 3
            except CrawlRepeatedCursor as exc:
                log(
                    f"crawl stopped after {exc.pages_fetched} pages: "
                    f"{STOP_REPEATED_CURSOR}; nothing written"
                )
                return 4
            except (httpx.HTTPError, ShapeMismatch) as exc:
                log(f"crawl failed, nothing written: {type(exc).__name__}")
                return 2
        log(
            f"crawl: {len(crawled.names)} names kept, "
            f"{crawled.invalid} invalid names skipped"
        )

    document = build_document(curated, crawled, date.today())
    OUTPUT.write_text(render(document), encoding="ascii")
    by_source = Counter(e["source"] for e in document["curated"])
    for listed in document["listed"].values():
        by_source[listed["source"]] += len(listed["names"])
    for source, count in sorted(by_source.items()):
        log(f"{count:6d}  {source}")
    log(f"wrote {sum(by_source.values())} entries to {OUTPUT}")
    if crawled is not None:
        log(f"crawl stopped after {crawled.pages_fetched} pages: {crawled.stop_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
