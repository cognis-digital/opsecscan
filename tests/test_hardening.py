"""Hardening tests: error paths, edge cases, and malformed-input guards."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from opsecscan import TOOL_NAME, TOOL_VERSION, scan_bytes  # noqa: E402
from opsecscan.cli import main  # noqa: E402
from opsecscan.core import scan_paths  # noqa: E402


# ---------------------------------------------------------------------------
# Identity / __init__ hardening
# ---------------------------------------------------------------------------

def test_tool_name_and_version_always_available():
    """TOOL_NAME and TOOL_VERSION must always resolve to non-empty strings."""
    assert isinstance(TOOL_NAME, str) and TOOL_NAME
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION
    # Version must be at least N.N.N
    assert TOOL_VERSION.count(".") >= 2


# ---------------------------------------------------------------------------
# CLI: bad / missing input → exit code 2, not traceback
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_exit_2(tmp_path, capsys):
    """A file that does not exist should produce a warning and exit 2
    (all results errored, none were actually scanned)."""
    rc = main(["scan", str(tmp_path / "does_not_exist.txt")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "does_not_exist.txt" in err


def test_cli_no_subcommand_returns_exit_2(capsys):
    """Running with no sub-command should print help and return 2."""
    rc = main([])
    assert rc == 2


def test_cli_invalid_severity_exits_nonzero(tmp_path):
    """An unrecognised --min-severity value must not produce a raw traceback."""
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    # argparse will call sys.exit(2) — that becomes SystemExit which is fine.
    try:
        rc = main(["scan", str(f), "--min-severity", "NOTASEVERITY"])
        assert rc != 0
    except SystemExit as exc:
        assert exc.code != 0


def test_cli_error_results_printed_to_stderr(tmp_path, capsys):
    """Files that cannot be read produce a stderr warning."""
    rc = main(["scan", str(tmp_path / "ghost.txt"), "--format", "json"])
    err = capsys.readouterr().err
    assert "ghost.txt" in err
    # exit 2: all files errored
    assert rc == 2


def test_cli_mixed_error_and_clean(tmp_path, capsys):
    """One readable clean file + one missing: exit 0, warning on stderr."""
    clean = tmp_path / "clean.txt"
    clean.write_text("all quiet\n", encoding="utf-8")
    rc = main(["scan", str(clean), str(tmp_path / "no_such.txt")])
    err = capsys.readouterr().err
    assert "no_such.txt" in err
    assert rc == 0  # readable file is clean, no leak → exit 0


# ---------------------------------------------------------------------------
# core: malformed / edge-case inputs
# ---------------------------------------------------------------------------

def test_scan_empty_bytes():
    """Empty input must not crash and must return a clean result."""
    res = scan_bytes(b"", "empty.txt")
    assert res.findings == []
    assert res.error == ""


def test_scan_bytes_empty_path():
    """Empty path string is accepted — uses '<bytes>' fallback."""
    res = scan_bytes(b"hello world", "")
    assert res.path == ""
    assert res.error == ""


def test_scan_malformed_jpeg_zero_seg_len():
    """A JPEG with a zero-length segment must not loop forever or crash."""
    # SOI + APP0 marker with seg_len=0 (malformed) — would previously loop.
    bad_jpeg = b"\xff\xd8" + b"\xff\xe0" + b"\x00\x00"
    res = scan_bytes(bad_jpeg, "malformed.jpg")
    assert res.file_type == "jpeg"
    assert res.error == ""  # handled gracefully, no exception


def test_scan_malformed_jpeg_seg_len_one():
    """seg_len == 1 is also malformed and must terminate cleanly."""
    bad_jpeg = b"\xff\xd8" + b"\xff\xe0" + b"\x00\x01"
    res = scan_bytes(bad_jpeg, "malformed2.jpg")
    assert res.file_type == "jpeg"
    assert res.error == ""


def test_scan_truncated_jpeg():
    """A truncated JPEG (no segments beyond SOI) returns no findings."""
    res = scan_bytes(b"\xff\xd8", "truncated.jpg")
    assert res.file_type == "jpeg"
    assert res.error == ""


def test_scan_truncated_tiff():
    """A TIFF header that is too short returns no findings."""
    res = scan_bytes(b"II*\x00", "short.tiff")
    assert res.file_type == "tiff"
    assert res.error == ""


def test_scan_bad_zip_as_docx():
    """Corrupt ZIP bytes disguised as .docx must not raise."""
    res = scan_bytes(b"PK\x03\x04not-a-real-zip", "broken.docx")
    assert res.file_type == "ooxml"
    assert res.error == ""
    assert res.findings == []


def test_scan_paths_empty_list():
    """scan_paths([]) returns an empty list without error."""
    assert scan_paths([]) == []


def test_scan_paths_directory_nonexistent(tmp_path):
    """A path that doesn't exist at all yields a single error result."""
    ghost = str(tmp_path / "ghost_dir" / "nope.txt")
    results = scan_paths([ghost])
    assert len(results) == 1
    assert results[0].error


def test_mcp_server_importable():
    """mcp_server must import cleanly (no broken top-level imports)."""
    import importlib
    mod = importlib.import_module("opsecscan.mcp_server")
    assert callable(mod.serve)
