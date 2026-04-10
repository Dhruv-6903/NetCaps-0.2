"""HTTP traffic extractor for files and credentials."""

import base64
import gzip
import hashlib
import io
import os
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import dpkt
except ImportError:
    dpkt = None

_EXTRACT_DIR = "/tmp/netcaps_extracted"
_HTTP_PORTS = {80, 8080, 8000, 8888}


def _ensure_extract_dir() -> None:
    os.makedirs(_EXTRACT_DIR, exist_ok=True)


def _compute_hashes(data: bytes) -> Tuple[str, str]:
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


@dataclass
class HTTPFile:
    timestamp: float
    filename: str
    url: str
    content_type: str
    size: int
    md5: str
    sha256: str
    session_id: int
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.filename, self.url, self.content_type,
            self.md5, self.sha256, str(self.session_id),
        ]).lower()


@dataclass
class HTTPCredential:
    timestamp: float
    username: str
    password: str
    method: str
    url: str
    session_id: int
    host: str = ""
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.username, self.password, self.method,
            self.url, self.host, str(self.session_id),
        ]).lower()


_FORM_USER_FIELDS = re.compile(
    r"(?:user(?:name)?|email|login|account|usr)=([^&\r\n]+)", re.IGNORECASE
)
_FORM_PASS_FIELDS = re.compile(
    r"(?:pass(?:word)?|passwd|pwd|secret)=([^&\r\n]+)", re.IGNORECASE
)


def _decode_chunked(data: bytes) -> bytes:
    """Decode HTTP chunked transfer encoding."""
    result = bytearray()
    idx = 0
    try:
        while idx < len(data):
            end = data.index(b"\r\n", idx)
            chunk_size = int(data[idx:end].split(b";")[0].strip(), 16)
            if chunk_size == 0:
                break
            start = end + 2
            result.extend(data[start : start + chunk_size])
            idx = start + chunk_size + 2
    except Exception:
        return bytes(data)
    return bytes(result)


def _parse_headers(header_block: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in header_block.split(b"\r\n"):
        if b":" in line:
            key, _, val = line.partition(b":")
            headers[key.strip().lower().decode("latin-1")] = val.strip().decode("latin-1")
    return headers


def _safe_filename(url: str, content_type: str) -> str:
    path = url.split("?")[0].rstrip("/")
    name = path.split("/")[-1] if "/" in path else path
    name = re.sub(r"[^\w\-.]", "_", name)
    if not name or name == "_":
        ext = ""
        if "html" in content_type:
            ext = ".html"
        elif "json" in content_type:
            ext = ".json"
        elif "javascript" in content_type:
            ext = ".js"
        elif "image" in content_type:
            ext = ".bin"
        name = "extracted_file" + ext
    return name


class HTTPExtractor:
    def __init__(self) -> None:
        self._session_buffers: Dict[int, Dict[str, bytes]] = {}

    def _get_buffer(self, session_id: int) -> Dict[str, bytes]:
        if session_id not in self._session_buffers:
            self._session_buffers[session_id] = {"sent": b"", "recv": b""}
        return self._session_buffers[session_id]

    def process_payload(
        self,
        timestamp: float,
        session_id: int,
        direction: str,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> Tuple[List[HTTPFile], List[HTTPCredential]]:
        if not payload:
            return [], []

        files: List[HTTPFile] = []
        creds: List[HTTPCredential] = []

        buf = self._get_buffer(session_id)
        buf[direction] += payload

        if direction == "sent":
            self._parse_request(timestamp, session_id, buf["sent"], creds)
        elif direction == "recv":
            self._parse_response(timestamp, session_id, buf["recv"], files)

        return files, creds

    def _parse_request(
        self,
        timestamp: float,
        session_id: int,
        data: bytes,
        creds: List[HTTPCredential],
    ) -> None:
        try:
            if b"\r\n\r\n" not in data:
                return

            header_end = data.index(b"\r\n\r\n")
            header_block = data[:header_end]
            body = data[header_end + 4 :]

            first_line, _, rest_headers = header_block.partition(b"\r\n")
            parts = first_line.split(b" ")
            if len(parts) < 2:
                return

            method = parts[0].decode("latin-1", errors="replace")
            path = parts[1].decode("latin-1", errors="replace")
            headers = _parse_headers(rest_headers)
            host = headers.get("host", "")
            url = f"http://{host}{path}" if host else path

            auth = headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth[6:]).decode("latin-1")
                    if ":" in decoded:
                        user, _, pwd = decoded.partition(":")
                        cred = HTTPCredential(
                            timestamp=timestamp,
                            username=user,
                            password=pwd,
                            method="HTTP Basic Auth",
                            url=url,
                            session_id=session_id,
                            host=host,
                        )
                        cred._update_search_str()
                        creds.append(cred)
                except Exception:
                    pass

            if method == "POST" and body:
                body_str = body.decode("latin-1", errors="replace")
                user_m = _FORM_USER_FIELDS.search(body_str)
                pass_m = _FORM_PASS_FIELDS.search(body_str)
                if user_m or pass_m:
                    username = urllib.parse.unquote_plus(user_m.group(1)) if user_m else ""
                    password = urllib.parse.unquote_plus(pass_m.group(1)) if pass_m else ""
                    if username or password:
                        cred = HTTPCredential(
                            timestamp=timestamp,
                            username=username,
                            password=password,
                            method="HTTP Form POST",
                            url=url,
                            session_id=session_id,
                            host=host,
                        )
                        cred._update_search_str()
                        creds.append(cred)
        except Exception:
            pass

    def _parse_response(
        self,
        timestamp: float,
        session_id: int,
        data: bytes,
        files: List[HTTPFile],
    ) -> None:
        try:
            if b"\r\n\r\n" not in data:
                return

            header_end = data.index(b"\r\n\r\n")
            header_block = data[:header_end]
            body = data[header_end + 4 :]

            first_line, _, rest_headers = header_block.partition(b"\r\n")
            headers = _parse_headers(rest_headers)
            content_type = headers.get("content-type", "application/octet-stream").split(";")[0].strip()
            transfer_encoding = headers.get("transfer-encoding", "")
            content_encoding = headers.get("content-encoding", "")

            if "chunked" in transfer_encoding:
                body = _decode_chunked(body)

            if "gzip" in content_encoding:
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass

            if not body or len(body) < 16:
                return

            skip_types = {"text/html", "text/css", "application/javascript", "text/javascript"}
            if content_type in skip_types:
                return

            url = ""
            filename = _safe_filename(url, content_type)
            md5, sha256 = _compute_hashes(body)

            try:
                _ensure_extract_dir()
                safe_name = f"sess{session_id}_{sha256[:8]}_{filename}"
                out_path = os.path.join(_EXTRACT_DIR, safe_name)
                with open(out_path, "wb") as f:
                    f.write(body)
            except Exception:
                out_path = ""

            rec = HTTPFile(
                timestamp=timestamp,
                filename=filename,
                url=url,
                content_type=content_type,
                size=len(body),
                md5=md5,
                sha256=sha256,
                session_id=session_id,
            )
            rec._update_search_str()
            files.append(rec)
        except Exception:
            pass

    def process_session_payloads(
        self,
        timestamp: float,
        session_id: int,
        payload_data: list,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> Tuple[List[HTTPFile], List[HTTPCredential]]:
        """Process all payloads for a completed/updated session."""
        if src_port not in _HTTP_PORTS and dst_port not in _HTTP_PORTS:
            return [], []

        all_files: List[HTTPFile] = []
        all_creds: List[HTTPCredential] = []

        buf = self._get_buffer(session_id)
        for direction, chunk in payload_data:
            buf[direction] += chunk

        self._parse_request(timestamp, session_id, buf["sent"], all_creds)
        self._parse_response(timestamp, session_id, buf["recv"], all_files)

        return all_files, all_creds
