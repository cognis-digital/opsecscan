"""Command-line interface for OPSECSCAN.

Usage:
    opsecscan scan FILE [FILE ...] [--recursive] [--format {table,json}]
                  [--min-severity LEVEL] [--fail-on LEVEL]
    opsecscan --version

Exit codes:
    0  no OPSEC leak at/above --fail-on threshold
    1  one or more files leaked at/above the threshold
    2  usage / IO error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import Severity, scan_paths

_LEVELS = {s.name.lower(): s for s in Severity}


def _severity(arg: str) -> Severity:
    key = arg.strip().lower()
    if key not in _LEVELS:
        raise argparse.ArgumentTypeError(
            f"invalid severity '{arg}' (choose from {', '.join(_LEVELS)})")
    return _LEVELS[key]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan documents and file metadata for OPSEC leaks "
                    "(GPS EXIF, author/creator metadata, unit identifiers, PII).")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    sc = sub.add_parser("scan", help="scan files or directories for OPSEC leaks")
    sc.add_argument("paths", nargs="+", help="files or directories to scan")
    sc.add_argument("-r", "--recursive", action="store_true",
                    help="recurse into directories")
    sc.add_argument("--format", choices=("table", "json"), default="table",
                    help="output format (default: table)")
    sc.add_argument("--min-severity", type=_severity, default=Severity.INFO,
                    help="hide findings below this severity")
    sc.add_argument("--fail-on", type=_severity, default=Severity.MEDIUM,
                    help="exit non-zero if any finding is at/above this "
                         "severity (default: medium)")
    return p


def _render_table(results, min_sev: Severity, fail_on: Severity) -> tuple[str, int]:
    lines: list[str] = []
    total_findings = 0
    leaked_files = 0
    for res in results:
        shown = [f for f in res.findings if f.severity >= min_sev]
        flagged = any(f.severity >= fail_on for f in res.findings)
        if flagged:
            leaked_files += 1
        header_mark = "LEAK" if flagged else "ok"
        lines.append(f"[{header_mark:>4}] {res.path}  ({res.file_type})")
        if res.error:
            lines.append(f"         ! error: {res.error}")
        for f in shown:
            total_findings += 1
            lines.append(
                f"         - {f.severity.label:<8} {f.category:<20} {f.detail}")
            if f.evidence:
                lines.append(f"               evidence: {f.evidence}")
        if not shown and not res.error:
            lines.append("         (clean)")
    lines.append("")
    lines.append(f"Scanned {len(results)} file(s); "
                 f"{leaked_files} leaked (>= {fail_on.label}); "
                 f"{total_findings} finding(s) shown.")
    return "\n".join(lines), leaked_files


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    results = scan_paths(args.paths, recursive=args.recursive)
    if not results:
        print("no files matched", file=sys.stderr)
        return 2

    fail_on: Severity = args.fail_on
    leaked_files = sum(1 for r in results if r.max_severity >= fail_on)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "fail_on": fail_on.label,
            "scanned": len(results),
            "leaked": leaked_files,
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(payload, indent=2))
    else:
        text, leaked_files = _render_table(results, args.min_severity, fail_on)
        print(text)

    return 1 if leaked_files else 0


if __name__ == "__main__":
    raise SystemExit(main())
