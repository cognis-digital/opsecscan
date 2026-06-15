"""OPSECSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from opsecscan.core import scan_paths


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-opsecscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-opsecscan[mcp]'",
              file=sys.stderr)
        return 1
    app = FastMCP("opsecscan")

    @app.tool()
    def opsecscan_scan(target: str) -> str:
        """Scan a file or directory for OPSEC leaks.

        Returns JSON findings including GPS EXIF, author/creator metadata,
        unit identifiers, and PII.
        """
        if not target or not target.strip():
            return json.dumps({"error": "target path must not be empty"})
        results = scan_paths([target.strip()])
        return json.dumps([r.to_dict() for r in results], indent=2)

    app.run()
    return 0
