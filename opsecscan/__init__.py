"""opsecscan — part of the Cognis Neural Suite."""
import importlib.metadata

from opsecscan.core import (  # noqa: F401
    Finding,
    Severity,
    ScanResult,
    scan_bytes,
    scan_path,
    scan_paths,
)

TOOL_NAME: str = "opsecscan"

try:
    TOOL_VERSION: str = importlib.metadata.version("cognis-opsecscan")
except importlib.metadata.PackageNotFoundError:  # running from source tree
    try:
        import os as _os
        _vf = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "VERSION")
        with open(_vf) as _f:
            TOOL_VERSION = _f.read().strip()
    except OSError:
        TOOL_VERSION = "0.0.0"

__version__ = TOOL_VERSION
