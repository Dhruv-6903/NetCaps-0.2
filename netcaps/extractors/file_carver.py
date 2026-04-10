"""File carver for extracting files from network streams."""

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

_EXTRACT_DIR = "/tmp/netcaps_extracted"

_SIGNATURES = [
    (b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (b"GIF87a", "image/gif", ".gif"),
    (b"GIF89a", "image/gif", ".gif"),
    (b"%PDF", "application/pdf", ".pdf"),
    (b"PK\x03\x04", "application/zip", ".zip"),
    (b"\x1f\x8b", "application/gzip", ".gz"),
    (b"BZh", "application/bzip2", ".bz2"),
    (b"\x7fELF", "application/elf", ".elf"),
    (b"MZ", "application/exe", ".exe"),
    (b"\xd0\xcf\x11\xe0", "application/msoffice", ".doc"),
    (b"Rar!\x1a\x07", "application/rar", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/7z", ".7z"),
]


def _detect_type(data: bytes) -> tuple:
    for sig, mime, ext in _SIGNATURES:
        if data[:len(sig)] == sig:
            return mime, ext
    return "application/octet-stream", ".bin"


def _compute_hashes(data: bytes):
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


@dataclass
class FileRecord:
    timestamp: float
    filename: str
    file_type: str
    size: int
    md5: str
    sha256: str
    path: str
    session_id: int
    vt_result: str = ""
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.filename, self.file_type,
            self.md5, self.sha256, str(self.session_id),
            self.vt_result,
        ]).lower()


class FileCarver:
    def carve(self, data: bytes, timestamp: float, session_id: int) -> Optional[FileRecord]:
        """Attempt to carve a file from raw bytes."""
        if len(data) < 16:
            return None

        mime, ext = _detect_type(data)
        if mime == "application/octet-stream":
            return None

        md5, sha256 = _compute_hashes(data)
        filename = f"carved_{sha256[:12]}{ext}"

        try:
            os.makedirs(_EXTRACT_DIR, exist_ok=True)
            out_path = os.path.join(_EXTRACT_DIR, filename)
            with open(out_path, "wb") as f:
                f.write(data)
        except Exception:
            out_path = ""

        rec = FileRecord(
            timestamp=timestamp,
            filename=filename,
            file_type=mime,
            size=len(data),
            md5=md5,
            sha256=sha256,
            path=out_path,
            session_id=session_id,
        )
        rec._update_search_str()
        return rec
