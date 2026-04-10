from __future__ import annotations

import base64
import gzip
import hashlib
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

import dpkt

from .models import CredentialRecord, DNSRecord, EmailRecord, FileRecord, TimelineEvent
from .store import CaseStore

USER_PAT = re.compile(r"(user(name)?|email)=([^&\s]+)", re.I)
PASS_PAT = re.compile(r"(pass(word)?|pwd)=([^&\s]+)", re.I)


class ArtifactExtractor:
    def __init__(self, store: CaseStore, extracted_dir: Path) -> None:
        self.store = store
        self.extracted_dir = extracted_dir
        self.extracted_dir.mkdir(parents=True, exist_ok=True)
        self.nx_counts: dict[str, int] = defaultdict(int)
        self.dns_counts: Counter[str] = Counter()

    def parse_dns(
        self, ts: float, src_ip: str, data: bytes, session_key: tuple[str, str, int, int, str] | None = None
    ) -> None:
        try:
            msg = dpkt.dns.DNS(data)
        except Exception:
            return
        if msg.qr != dpkt.dns.DNS_Q:
            return
        query = msg.qd[0].name if msg.qd else ""
        qtype = str(msg.qd[0].type if msg.qd else "")
        status = str(msg.rcode)
        answers = [getattr(a, "name", "") for a in msg.an if msg.an]
        rec = DNSRecord(timestamp=ts, src_ip=src_ip, query=query, qtype=qtype, status=status, answers=answers)
        self.dns_counts[src_ip] += 1
        if msg.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
            self.nx_counts[src_ip] += 1
            if self.nx_counts[src_ip] > 20:
                rec.anomaly_flags.append("NXDOMAIN_SPIKE")
        if query and self._domain_entropy(query) > 3.8:
            rec.anomaly_flags.append("HIGH_ENTROPY_DOMAIN")
        self.store.add_dns(rec)
        self.store.add_timeline(TimelineEvent(ts, "dns", f"DNS query {query}", {"session_key": session_key}))

    @staticmethod
    def _domain_entropy(domain: str) -> float:
        if not domain:
            return 0.0
        counts = Counter(domain)
        n = len(domain)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    def parse_http(
        self, ts: float, payload: bytes, session_key: tuple[str, str, int, int, str] | None = None
    ) -> None:
        try:
            req = dpkt.http.Request(payload)
        except Exception:
            req = None
        if req:
            auth = req.headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", errors="ignore")
                    if ":" in decoded:
                        user, pwd = decoded.split(":", 1)
                        self._add_cred(ts, "HTTP_BASIC", user, pwd, "http-header", session_key)
                except Exception:
                    pass
            if req.method == "POST":
                body = bytes(req.body).decode("utf-8", errors="ignore")
                u = USER_PAT.search(body)
                p = PASS_PAT.search(body)
                if u and p:
                    self._add_cred(ts, "HTTP_FORM", u.group(3), p.group(3), "http-post", session_key)
            return

        try:
            resp = dpkt.http.Response(payload)
        except Exception:
            return
        filename = resp.headers.get("content-disposition", "").split("filename=")[-1].strip("\"' ")
        if not filename:
            filename = f"http_{int(ts * 1000)}.bin"
        body = bytes(resp.body)
        if resp.headers.get("transfer-encoding", "").lower() == "chunked":
            body = self._decode_chunked(body)
        if resp.headers.get("content-encoding", "").lower() == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        self._carve_file(ts, "http", filename, resp.headers.get("content-type"), body, session_key)

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j < 0:
                break
            size_str = data[i:j].split(b";", 1)[0]
            try:
                size = int(size_str, 16)
            except ValueError:
                break
            if size == 0:
                break
            start = j + 2
            out.extend(data[start : start + size])
            i = start + size + 2
        return bytes(out)

    def parse_ftp(
        self, ts: float, text: str, session_key: tuple[str, str, int, int, str] | None = None
    ) -> None:
        lines = [l.strip() for l in text.splitlines()]
        user: str | None = None
        pwd: str | None = None
        for line in lines:
            if line.upper().startswith("USER "):
                user = line[5:].strip()
            elif line.upper().startswith("PASS "):
                pwd = line[5:].strip()
        if user and pwd:
            self._add_cred(ts, "FTP", user, pwd, "ftp", session_key)

    def parse_smtp(
        self, ts: float, text: str, session_key: tuple[str, str, int, int, str] | None = None
    ) -> None:
        sender = receiver = subject = None
        body_preview = ""
        attachments: list[str] = []
        lines = text.splitlines()
        in_body = False
        for i, line in enumerate(lines):
            upper = line.upper()
            if upper.startswith("AUTH LOGIN") and i + 2 < len(lines):
                try:
                    user = base64.b64decode(lines[i + 1]).decode(errors="ignore")
                    pwd = base64.b64decode(lines[i + 2]).decode(errors="ignore")
                    self._add_cred(ts, "SMTP_AUTH_LOGIN", user, pwd, "smtp", session_key)
                except Exception:
                    pass
            if line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            elif line.lower().startswith("to:"):
                receiver = line.split(":", 1)[1].strip()
            elif line.lower().startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            elif line.strip() == "":
                in_body = True
                continue
            elif in_body and len(body_preview) < 300:
                body_preview += line[:120] + " "
            if "filename=" in line.lower():
                name = line.split("filename=", 1)[1].strip("\"' ")
                if name:
                    attachments.append(name)
        email = EmailRecord(ts, sender, receiver, subject, body_preview.strip(), attachments, session_key)
        self.store.add_email(email)
        self.store.add_timeline(TimelineEvent(ts, "email", f"Email {subject or '(no subject)'}", {}))

    def _carve_file(
        self,
        ts: float,
        source: str,
        filename: str,
        content_type: str | None,
        body: bytes,
        session_key: tuple[str, str, int, int, str] | None = None,
    ) -> None:
        if not body:
            return
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)[:128]
        path = self.extracted_dir / safe_name
        path.write_bytes(body)
        md5 = hashlib.md5(body).hexdigest()
        sha256 = hashlib.sha256(body).hexdigest()
        rec = FileRecord(ts, source, safe_name, content_type, len(body), md5, sha256, str(path), session_key)
        self.store.add_file(rec)
        self.store.add_timeline(TimelineEvent(ts, "file", f"Extracted file {safe_name}", {"path": str(path)}))

    def _add_cred(
        self,
        ts: float,
        protocol: str,
        username: str,
        password: str,
        source: str,
        session_key: tuple[str, str, int, int, str] | None,
    ) -> None:
        rec = CredentialRecord(ts, protocol, username, password, source, session_key)
        self.store.add_credential(rec)
        self.store.add_timeline(TimelineEvent(ts, "credential", f"Credential found for {username}", {}))
