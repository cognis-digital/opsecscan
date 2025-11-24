"""Core OPSEC-leak scanning engine.

Pure standard library. Inspects file bytes and structured metadata for content
that commonly leaks operational security:

  * GPS / geolocation EXIF in JPEG/TIFF images
  * Author / creator / producer / last-modified-by metadata in office &
    PDF documents
  * Embedded geotags and coordinate strings in text
  * Unit identifiers, callsigns, classification banners, and personnel PII
    that should not appear in a public release

Everything is read-only. The engine never modifies inputs.
"""
from __future__ import annotations

import io
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Iterable


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    category: str          # e.g. "gps_exif", "author", "unit_identifier"
    severity: Severity
    detail: str            # human-readable description
    evidence: str = ""     # the offending value (redacted/truncated)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = self.severity.label
        return d


@dataclass
class ScanResult:
    path: str
    file_type: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def leaked(self) -> bool:
        # MEDIUM+ is treated as a real OPSEC leak that should gate a release.
        return self.max_severity >= Severity.MEDIUM

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "file_type": self.file_type,
            "max_severity": int(self.max_severity),
            "max_severity_label": self.max_severity.label,
            "leaked": self.leaked,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# Text / metadata pattern detectors
# --------------------------------------------------------------------------

# Unit identifiers, callsigns, and classification banners commonly found in
# operational documents. These are intentionally generic and public-knowledge
# formatting conventions; the tool only FLAGS their presence so an author can
# scrub a document before release.
UNIT_PATTERNS: list[tuple[str, str, Severity]] = [
    ("classification_banner",
     r"\b(?:TOP SECRET|SECRET//[A-Z/]+|CONFIDENTIAL//|NOFORN|FOUO|CUI//?[A-Z]*)\b",
     Severity.CRITICAL),
    ("unit_identifier",
     r"\b\d{1,3}(?:st|nd|rd|th)\s+(?:Infantry|Airborne|Armored|Cavalry|Marine|Aviation|Sustainment|Brigade|Battalion|Regiment|Division|Squadron)\b",
     Severity.HIGH),
    ("unit_identifier",
     r"\b(?:1st|2nd|3rd|[0-9]{1,3}th)\s*(?:BCT|BDE|BN|CO|PLT|RGT|DIV)\b",
     Severity.HIGH),
    ("callsign",
     r"\bcallsign[:\s]+[A-Z][A-Z0-9-]{2,}\b",
     Severity.MEDIUM),
    ("coordinates_mgrs",
     r"\b\d{1,2}[C-X][A-Z]{2}\d{4,10}\b",
     Severity.HIGH),
    ("coordinates_latlon",
     r"[-+]?\d{1,2}\.\d{4,}\s*,\s*[-+]?\d{1,3}\.\d{4,}",
     Severity.HIGH),
    ("pii_ssn",
     r"\b\d{3}-\d{2}-\d{4}\b",
     Severity.CRITICAL),
    ("pii_dod_id",
     r"\bDoD\s*ID[:\s#]*\d{10}\b",
     Severity.HIGH),
    ("pii_email",
     r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*(?:mil|gov)\b",
     Severity.MEDIUM),
]

_COMPILED_UNIT = [(cat, re.compile(rx, re.IGNORECASE), sev) for cat, rx, sev in UNIT_PATTERNS]

_METADATA_KEYS = {
    "author": Severity.MEDIUM,
    "creator": Severity.MEDIUM,
    "producer": Severity.LOW,
    "lastmodifiedby": Severity.MEDIUM,
    "last-author": Severity.MEDIUM,
    "company": Severity.LOW,
    "manager": Severity.LOW,
}


def _truncate(value: str, n: int = 120) -> str:
    value = value.strip().replace("\n", " ")
    return value if len(value) <= n else value[:n] + "..."


def _scan_text(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for cat, rx, sev in _COMPILED_UNIT:
        for m in rx.finditer(text):
            ev = _truncate(m.group(0))
            key = (cat, ev)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(cat, sev, f"{cat} pattern present in text/metadata", ev))
    return out


# --------------------------------------------------------------------------
# JPEG / EXIF parsing (minimal, stdlib only)
# --------------------------------------------------------------------------

_EXIF_GPS_IFD_TAG = 0x8825
_EXIF_SUB_IFD_TAG = 0x8769
_TAG_ARTIST = 0x013B
_TAG_SOFTWARE = 0x0131
_TAG_DATETIME = 0x0132


def _parse_tiff_for_gps(data: bytes) -> list[Finding]:
    """Parse a TIFF/EXIF block; report GPS IFD presence and camera metadata."""
    findings: list[Finding] = []
    if len(data) < 8:
        return findings
    byte_order = data[0:2]
    if byte_order == b"II":
        endian = "<"
    elif byte_order == b"MM":
        endian = ">"
    else:
        return findings

    def u16(off): return struct.unpack(endian + "H", data[off:off + 2])[0]
    def u32(off): return struct.unpack(endian + "I", data[off:off + 4])[0]

    try:
        magic = u16(2)
        if magic != 42:
            return findings
        ifd_off = u32(4)
    except struct.error:
        return findings

    def read_ifd(offset: int) -> dict[int, int]:
        tags: dict[int, int] = {}
        if offset <= 0 or offset + 2 > len(data):
            return tags
        try:
            count = u16(offset)
        except struct.error:
            return tags
        entry = offset + 2
        for _ in range(count):
            if entry + 12 > len(data):
                break
            tag = u16(entry)
            value_off = entry + 8
            tags[tag] = value_off
            entry += 12
        return tags

    def read_ascii(value_off: int) -> str:
        try:
            typ = u16(value_off - 6)
            cnt = u32(value_off - 4)
        except struct.error:
            return ""
        if typ != 2 or cnt <= 0 or cnt > 4096:
            return ""
        if cnt <= 4:
            raw = data[value_off:value_off + cnt]
        else:
            try:
                ptr = u32(value_off)
            except struct.error:
                return ""
            raw = data[ptr:ptr + cnt]
        return raw.split(b"\x00")[0].decode("latin-1", "replace")

    tags = read_ifd(ifd_off)

    if _EXIF_GPS_IFD_TAG in tags:
        try:
            gps_ptr = u32(tags[_EXIF_GPS_IFD_TAG])
        except struct.error:
            gps_ptr = 0
        gps_tags = read_ifd(gps_ptr) if gps_ptr else {}
        if gps_tags:
            findings.append(Finding(
                "gps_exif", Severity.CRITICAL,
                "Image contains a GPS EXIF IFD (geolocation embedded)",
                f"{len(gps_tags)} GPS tag(s)"))
        else:
            findings.append(Finding(
                "gps_exif", Severity.HIGH,
                "Image references a GPS IFD", "GPSInfo tag present"))

    if _TAG_ARTIST in tags:
        v = read_ascii(tags[_TAG_ARTIST])
        if v:
            findings.append(Finding("author", Severity.MEDIUM,
                                    "EXIF Artist/author field set", _truncate(v)))
    if _TAG_SOFTWARE in tags:
        v = read_ascii(tags[_TAG_SOFTWARE])
        if v:
            findings.append(Finding("software", Severity.LOW,
                                    "EXIF Software field set", _truncate(v)))
    if _TAG_DATETIME in tags:
        v = read_ascii(tags[_TAG_DATETIME])
        if v:
            findings.append(Finding("timestamp", Severity.LOW,
                                    "EXIF DateTime present", _truncate(v)))
    return findings


def _scan_jpeg(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    i = 2  # skip SOI
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if i + 4 > n:
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        seg = data[i + 4:i + 2 + seg_len]
        if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            findings.extend(_parse_tiff_for_gps(seg[6:]))
        elif marker == 0xFE:  # COM comment
            txt = seg.decode("latin-1", "replace")
            findings.append(Finding("comment", Severity.LOW,
                                    "JPEG comment segment present", _truncate(txt)))
            findings.extend(_scan_text(txt))
        if marker == 0xDA:  # start of scan; metadata is done
            break
        i += 2 + seg_len
    return findings


def _scan_tiff(data: bytes) -> list[Finding]:
    return _parse_tiff_for_gps(data)


# --------------------------------------------------------------------------
# Office Open XML (docx/xlsx/pptx) metadata
# --------------------------------------------------------------------------

def _scan_ooxml(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return findings
    for meta in ("docProps/core.xml", "docProps/app.xml"):
        if meta not in zf.namelist():
            continue
        try:
            xml = zf.read(meta).decode("utf-8", "replace")
        except Exception:
            continue
        for tag, sev in _METADATA_KEYS.items():
            # match <ns:Tag>value</ns:Tag> or <dc:tag>value</dc:tag>
            for m in re.finditer(
                rf"<[^>]*?\b{re.escape(tag)}\b[^>]*>([^<]+)<", xml, re.IGNORECASE
            ):
                val = m.group(1).strip()
                if val:
                    findings.append(Finding(
                        tag.replace("-", "_"), sev,
                        f"OOXML document property '{tag}' is set", _truncate(val)))
    return findings


# --------------------------------------------------------------------------
# PDF metadata (Info dictionary, plain-string scan)
# --------------------------------------------------------------------------

def _scan_pdf(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    text = data.decode("latin-1", "replace")
    for key, sev in (("Author", Severity.MEDIUM), ("Creator", Severity.MEDIUM),
                     ("Producer", Severity.LOW)):
        for m in re.finditer(rf"/{key}\s*\(([^)]*)\)", text):
            val = m.group(1).strip()
            if val:
                findings.append(Finding(
                    key.lower(), sev, f"PDF Info /{key} is set", _truncate(val)))
    # XMP packet often carries dc:creator etc.
    findings.extend(_scan_text(text))
    return findings


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

def _detect_type(data: bytes, path: str = "") -> str:
    if data[:2] == b"\xff\xd8":
        return "jpeg"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        # could be ooxml or generic zip
        ext = os.path.splitext(path)[1].lower()
        if ext in (".docx", ".xlsx", ".pptx"):
            return "ooxml"
        # peek for docProps
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            if any(nm.startswith("docProps/") for nm in zf.namelist()):
                return "ooxml"
        except zipfile.BadZipFile:
            pass
        return "zip"
    return "text"


def scan_bytes(data: bytes, path: str = "<bytes>") -> ScanResult:
    ftype = _detect_type(data, path)
    res = ScanResult(path=path, file_type=ftype)
    try:
        if ftype == "jpeg":
            res.findings.extend(_scan_jpeg(data))
        elif ftype == "tiff":
            res.findings.extend(_scan_tiff(data))
        elif ftype == "pdf":
            res.findings.extend(_scan_pdf(data))
        elif ftype == "ooxml":
            res.findings.extend(_scan_ooxml(data))
        elif ftype in ("text", "zip"):
            txt = data.decode("utf-8", "replace")
            res.findings.extend(_scan_text(txt))
    except Exception as exc:  # never crash a scan on one bad file
        res.error = f"{type(exc).__name__}: {exc}"
    res.findings.sort(key=lambda f: int(f.severity), reverse=True)
    return res


def scan_path(path: str) -> ScanResult:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return ScanResult(path=path, file_type="?", error=f"{type(exc).__name__}: {exc}")
    return scan_bytes(data, path)


def _iter_files(paths: Iterable[str], recursive: bool) -> Iterable[str]:
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for f in files:
                        yield os.path.join(root, f)
            else:
                for f in sorted(os.listdir(p)):
                    fp = os.path.join(p, f)
                    if os.path.isfile(fp):
                        yield fp
        else:
            yield p


def scan_paths(paths: Iterable[str], recursive: bool = False) -> list[ScanResult]:
    return [scan_path(fp) for fp in _iter_files(paths, recursive)]
