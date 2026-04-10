"""FTP traffic parser for credential extraction."""

import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import dpkt
except ImportError:
    dpkt = None


@dataclass
class FTPCredential:
    timestamp: float
    username: str
    password: str
    server_ip: str
    client_ip: str
    session_id: int
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.username, self.password,
            self.server_ip, self.client_ip,
            str(self.session_id),
        ]).lower()


class FTPParser:
    def __init__(self) -> None:
        # session_id -> partial credentials
        self._pending: Dict[int, Dict[str, str]] = {}

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
    ) -> Optional[FTPCredential]:
        if src_port != 21 and dst_port != 21:
            return None

        try:
            text = payload.decode("latin-1", errors="replace").strip()
        except Exception:
            return None

        # client -> server direction
        if dst_port == 21 or direction == "sent":
            upper = text.upper()
            if session_id not in self._pending:
                self._pending[session_id] = {"user": "", "pass": "", "server": dst_ip, "client": src_ip}

            if upper.startswith("USER "):
                self._pending[session_id]["user"] = text[5:].strip()
            elif upper.startswith("PASS "):
                self._pending[session_id]["pass"] = text[5:].strip()
                pend = self._pending.pop(session_id)
                cred = FTPCredential(
                    timestamp=timestamp,
                    username=pend["user"],
                    password=pend["pass"],
                    server_ip=pend["server"],
                    client_ip=pend["client"],
                    session_id=session_id,
                )
                cred._update_search_str()
                return cred

        return None
