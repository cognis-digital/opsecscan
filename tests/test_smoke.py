"""Smoke tests for OPSECSCAN. Standard library only, no network."""
import io
import os
import struct
import sys
import zipfile


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from opsecscan import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Severity,
    scan_bytes,
    scan_path,
)
from opsecscan.cli import main  # noqa: E402


def test_exports():
    assert TOOL_NAME == "opsecscan"
    assert TOOL_VERSION.count(".") == 2


def test_text_detects_classification_and_pii():
    data = (b"SECRET//NOFORN\n3rd Infantry Division\n"
            b"coords 34.052200, -118.243700\nSSN 123-45-6789\n")
    res = scan_bytes(data, "note.txt")
    cats = {f.category for f in res.findings}
    assert "classification_banner" in cats
    assert "unit_identifier" in cats
    assert "coordinates_latlon" in cats
    assert "pii_ssn" in cats
    assert res.max_severity == Severity.CRITICAL
    assert res.leaked is True


def test_clean_text_no_leak():
    res = scan_bytes(b"The weather was pleasant and morale was high.\n", "x.txt")
    assert res.findings == []
    assert res.leaked is False
    assert res.max_severity == Severity.INFO


def _make_jpeg_with_gps() -> bytes:
    # Build a minimal JPEG: SOI + APP1/Exif(TIFF with a GPSInfo tag) + EOI.
    # TIFF (little endian), one IFD entry: tag=0x8825 (GPSInfo), type=LONG, count=1, value=offset.
    tiff = bytearray()
    tiff += b"II"                 # endian
    tiff += struct.pack("<H", 42) # magic
    tiff += struct.pack("<I", 8)  # offset to IFD0
    # IFD0
    ifd0_off = len(tiff)
    gps_ifd_off = ifd0_off + 2 + 12 + 4  # after this IFD + next-IFD ptr
    tiff += struct.pack("<H", 1)               # 1 entry
    tiff += struct.pack("<H", 0x8825)          # GPSInfo tag
    tiff += struct.pack("<H", 4)               # type LONG
    tiff += struct.pack("<I", 1)               # count
    tiff += struct.pack("<I", gps_ifd_off)     # value = offset to GPS IFD
    tiff += struct.pack("<I", 0)               # next IFD = 0
    # GPS IFD with one (dummy) entry so it is non-empty
    tiff += struct.pack("<H", 1)               # 1 entry
    tiff += struct.pack("<H", 0x0002)          # GPSLatitude tag
    tiff += struct.pack("<H", 5)               # type RATIONAL
    tiff += struct.pack("<I", 1)               # count
    tiff += struct.pack("<I", 0)               # value
    tiff += struct.pack("<I", 0)               # next IFD

    exif_payload = b"Exif\x00\x00" + bytes(tiff)
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
    return b"\xff\xd8" + app1 + b"\xff\xd9"


def test_jpeg_gps_exif_detected():
    res = scan_bytes(_make_jpeg_with_gps(), "photo.jpg")
    assert res.file_type == "jpeg"
    cats = {f.category for f in res.findings}
    assert "gps_exif" in cats
    assert res.max_severity == Severity.CRITICAL


def _make_docx_with_author() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "docProps/core.xml",
            '<?xml version="1.0"?>'
            '<cp:coreProperties xmlns:cp="x" xmlns:dc="y">'
            '<dc:creator>Jane Analyst</dc:creator>'
            '<cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>'
            '</cp:coreProperties>',
        )
    return buf.getvalue()


def test_ooxml_metadata_detected():
    res = scan_bytes(_make_docx_with_author(), "report.docx")
    assert res.file_type == "ooxml"
    cats = {f.category for f in res.findings}
    assert "creator" in cats
    assert "lastmodifiedby" in cats


def test_pdf_author_detected():
    data = b"%PDF-1.4\n1 0 obj<< /Author (COL Smith) /Producer (Acme) >>endobj\n"
    res = scan_bytes(data, "brief.pdf")
    assert res.file_type == "pdf"
    cats = {f.category for f in res.findings}
    assert "author" in cats


def test_cli_json_and_exit_code(tmp_path, capsys):
    leak = tmp_path / "leak.txt"
    leak.write_text("SECRET//NOFORN unit 1st BCT\n", encoding="utf-8")
    rc = main(["scan", str(leak), "--format", "json"])
    assert rc == 1
    out = capsys.readouterr().out
    assert '"tool": "opsecscan"' in out
    assert '"leaked": 1' in out


def test_cli_clean_exit_zero(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("all quiet, nothing to report\n", encoding="utf-8")
    rc = main(["scan", str(clean)])
    assert rc == 0


def test_cli_fail_on_threshold(tmp_path):
    # author metadata is MEDIUM; with --fail-on high it should not gate.
    f = tmp_path / "a.pdf"
    f.write_bytes(b"%PDF-1.4\n<< /Author (Jane) >>\n")
    assert main(["scan", str(f), "--fail-on", "high"]) == 0
    assert main(["scan", str(f), "--fail-on", "medium"]) == 1


def test_missing_file_reports_error():
    res = scan_path("/no/such/file/exists.xyz")
    assert res.error
    assert res.findings == []
