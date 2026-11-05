"""OWASP MCP Top 10 ids and titles.

Copied verbatim from https://owasp.org/www-project-mcp-top-10/ on 2026-11-02, when the
project was in "Phase 3 – Beta Release and Pilot Testing". Re-check the page before
editing; do not fill in ids from memory. Note the page titles MCP06 "Prompt Injection via
Contextual Payloads" although its link slug says "Intent-Flow-Subversion"; the title wins.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

SOURCE_URL: Final = "https://owasp.org/www-project-mcp-top-10/"

OWASP_MCP_TOP_10: Final[Mapping[str, str]] = MappingProxyType(
    {
        "MCP01:2025": "Token Mismanagement & Secret Exposure",
        "MCP02:2025": "Privilege Escalation via Scope Creep",
        "MCP03:2025": "Tool Poisoning",
        "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
        "MCP05:2025": "Command Injection & Execution",
        "MCP06:2025": "Prompt Injection via Contextual Payloads",
        "MCP07:2025": "Insufficient Authentication & Authorization",
        "MCP08:2025": "Lack of Audit and Telemetry",
        "MCP09:2025": "Shadow MCP Servers",
        "MCP10:2025": "Context Injection & Over-Sharing",
    }
)
