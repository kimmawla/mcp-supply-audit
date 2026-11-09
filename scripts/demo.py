"""Demo: run the published mcp-supply-audit server and print a readable audit_server summary.

Dev-only: run by hand. Never imported by src/. Starts the published server with
`uvx mcp-supply-audit` over stdio through fastmcp.Client, calls audit_server for
io.github.kimmawla/vuln-triage-mcp, and prints today's date and a compact summary: audited
versions, severity counts, each finding as `rule_id: title` with its location (never evidence
text), the checks that ran, each skipped check with its reason and detail, the notes, and
data_sources. The server's stderr goes to os.devnull, so only this summary is printed.

Every string from the report is printed with non-printable and non-ASCII characters shown as
visible \\uXXXX escapes. The summary is readable text, not JSON.

Usage: uv run scripts/demo.py
Exit status: 0 printed, 1 the tool returned an error or no report.
"""

import asyncio
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

PACKAGE = "mcp-supply-audit"
TARGET = "io.github.kimmawla/vuln-triage-mcp"
CALL_TIMEOUT_SECONDS = 90  # the server's own deadline is 30 s; uvx may download first
SEVERITIES = ("critical", "high", "medium", "low", "info")


def visible(value: Any) -> str:
    """Report text with every non-printable or non-ASCII character as a \\uXXXX escape."""
    return "".join(c if " " <= c <= "~" else f"\\u{ord(c):04x}" for c in str(value))


async def fetch_report() -> dict[str, Any]:
    transport = StdioTransport(command="uvx", args=[PACKAGE], log_file=Path(os.devnull))
    async with Client(transport) as client:
        result = await client.call_tool(
            "audit_server",
            {"name": TARGET},
            timeout=CALL_TIMEOUT_SECONDS,
            raise_on_error=False,
        )
    if result.is_error:
        raise RuntimeError("audit_server returned an error")
    report = result.structured_content
    if isinstance(report, dict) and "findings" not in report and "result" in report:
        report = report["result"]
    if not isinstance(report, dict):
        text = "".join(getattr(c, "text", "") for c in result.content)
        report = json.loads(text)
    if not isinstance(report, dict) or "findings" not in report:
        raise RuntimeError("audit_server returned no report")
    return report


def summarize(report: dict[str, Any]) -> list[str]:
    lines = [f"Date: {date.today().isoformat()}", f"Target: {TARGET}", ""]

    audited = report.get("audited_by_report") or {}
    if report.get("audited"):
        audited = {"audit_package": report["audited"], **audited}
    lines.append("Audited versions:")
    if audited:
        for sub, pkg in audited.items():
            lines.append(
                f"  {visible(pkg.get('ecosystem'))} {visible(pkg.get('name'))} "
                f"{visible(pkg.get('version'))}  ({visible(sub)})"
            )
    else:
        lines.append("  (none reported)")
    lines.append("")

    summary = report.get("summary") or {}
    counts = ", ".join(f"{s} {summary.get(s, 0)}" for s in SEVERITIES)
    lines.append(f"Severity counts: {counts}")
    lines.append(f"Assessment: {visible(report.get('assessment'))}")
    lines.append("")

    findings = report.get("findings") or []
    lines.append(f"Findings ({len(findings)}):")
    for f in findings:
        lines.append(
            f"  [{visible(f.get('severity'))}] {visible(f.get('rule_id'))}: "
            f"{visible(f.get('title'))}"
        )
        lines.append(f"      at {visible(f.get('location'))}")
    if not findings:
        lines.append("  (none detected by the checks that ran)")
    lines.append("")

    coverage = report.get("coverage") or {}
    ran = coverage.get("ran") or []
    lines.append(f"Checks that ran ({len(ran)}):")
    lines.extend(f"  {visible(check)}" for check in ran)
    lines.append("")

    skipped = coverage.get("skipped") or []
    lines.append(f"Skipped checks ({len(skipped)}):")
    for s in skipped:
        detail = f" ({visible(s['detail'])})" if s.get("detail") else ""
        lines.append(f"  {visible(s.get('check'))}: {visible(s.get('reason'))}{detail}")
    lines.append("")

    notes = report.get("notes") or []
    lines.append("Notes:")
    lines.extend(f"  - {visible(n)}" for n in notes)
    lines.append(f"  - {visible(report.get('note'))}")
    lines.append("")

    sources = report.get("data_sources") or []
    lines.append("Data sources:")
    for d in sources:
        partial = ", partial" if d.get("partial") else ""
        lines.append(
            f"  {visible(d.get('name'))}: as of {visible(d.get('as_of'))}, "
            f"{visible(d.get('entry_count'))} entries{partial}"
        )
    if not sources:
        lines.append("  (none)")
    return lines


def main() -> int:
    try:
        report = asyncio.run(fetch_report())
    except Exception as exc:  # noqa: BLE001 - one fixed message, type name only
        sys.stderr.write(f"demo failed: {type(exc).__name__}\n")
        return 1
    sys.stdout.write("\n".join(summarize(report)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
