def main() -> None:
    """Run the MCP server over stdio (same as the mcp-supply-audit console script)."""
    # Imported here so importing the package does not build the server.
    from mcp_supply_audit.server import main as run_server

    run_server()
