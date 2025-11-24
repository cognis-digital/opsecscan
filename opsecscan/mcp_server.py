"""OPSECSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from opsecscan.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-opsecscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-opsecscan[mcp]'")
        return 1
    app = FastMCP("opsecscan")

    @app.tool()
    def opsecscan_scan(target: str) -> str:
        """Scan documents and file metadata for OPSEC leaks: geotags, author, GPS EXIF, unit identifiers.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
