"""ToolError carrying the skip reason a caller records when a whole check could not run."""

from fastmcp.exceptions import ToolError

from mcp_supply_audit.findings import SkipDetail, SkipReason


class NoChecksRan(ToolError):
    """Raised by a tool function when nothing could run. The message is a fixed string;
    audit_server records `reason` and `detail` as a skipped check instead of failing."""

    def __init__(
        self, message: str, reason: SkipReason, detail: SkipDetail | None = None
    ) -> None:
        super().__init__(message)
        self.reason = SkipReason(reason)
        self.detail = None if detail is None else SkipDetail(detail)
