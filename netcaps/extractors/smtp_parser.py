"""SMTP traffic parser for email extraction."""

import base64
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_ATTACH_DIR = "/tmp/netcaps_extracted/attachments"


def _ensure_attach_dir() -> None:
    os.makedirs(_ATTACH_DIR, exist_ok=True)


@dataclass
class EmailRecord:
    timestamp: float
    sender: str
    receiver: str
    subject: str
    body_preview: str
    attachments: List[str] = field(default_factory=list)
    session_id: int = 0
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.sender, self.receiver, self.subject,
            self.body_preview, " ".join(self.attachments),
            str(self.session_id),
        ]).lower()


_SMTP_PORTS = {25, 587, 465}


class SMTPParser:
    def __init__(self) -> None:
        self._state: Dict[int, Dict] = {}

    def _get_state(self, session_id: int) -> Dict:
        if session_id not in self._state:
            self._state[session_id] = {
                "sender": "",
                "receiver": "",
                "subject": "",
                "body": b"",
                "in_data": False,
                "auth_user": "",
                "auth_step": 0,
                "attachments": [],
                "timestamp": 0.0,
            }
        return self._state[session_id]

    def process_payload(
        self,
        timestamp: float,
        session_id: int,
        direction: str,
        payload: bytes,
        src_port: int,
        dst_port: int,
    ) -> Optional[EmailRecord]:
        if src_port not in _SMTP_PORTS and dst_port not in _SMTP_PORTS:
            return None

        state = self._get_state(session_id)
        if state["timestamp"] == 0.0:
            state["timestamp"] = timestamp

        try:
            text = payload.decode("latin-1", errors="replace")
        except Exception:
            return None

        if direction == "sent" or dst_port in _SMTP_PORTS:
            return self._handle_client(text, state, session_id, timestamp)

        return None

    def _handle_client(self, text: str, state: Dict, session_id: int, timestamp: float) -> Optional[EmailRecord]:
        lines = text.splitlines()
        result = None

        for line in lines:
            stripped = line.strip()
            upper = stripped.upper()

            if state["in_data"]:
                if stripped == ".":
                    state["in_data"] = False
                    result = self._build_email(state, session_id)
                    self._state.pop(session_id, None)
                    break
                else:
                    # Parse headers/body
                    if stripped.lower().startswith("subject:"):
                        state["subject"] = stripped[8:].strip()
                    elif stripped.lower().startswith("content-disposition: attachment"):
                        m = re.search(r'filename="?([^";\r\n]+)"?', stripped, re.IGNORECASE)
                        if m:
                            fname = m.group(1).strip()
                            state["attachments"].append(fname)
                            try:
                                _ensure_attach_dir()
                            except Exception:
                                pass
                    else:
                        state["body"] += (line + "\n").encode("latin-1", errors="replace")
            elif upper.startswith("MAIL FROM:"):
                addr = re.sub(r"[<>]", "", stripped[10:]).strip()
                state["sender"] = addr
            elif upper.startswith("RCPT TO:"):
                addr = re.sub(r"[<>]", "", stripped[8:]).strip()
                state["receiver"] = addr
            elif upper == "DATA":
                state["in_data"] = True
            elif upper.startswith("AUTH LOGIN"):
                state["auth_step"] = 1
            elif state["auth_step"] == 1:
                try:
                    state["auth_user"] = base64.b64decode(stripped).decode("latin-1")
                    state["auth_step"] = 2
                except Exception:
                    state["auth_step"] = 0
            elif state["auth_step"] == 2:
                try:
                    pwd = base64.b64decode(stripped).decode("latin-1")
                    state["auth_step"] = 0
                except Exception:
                    state["auth_step"] = 0

        return result

    def _build_email(self, state: Dict, session_id: int) -> EmailRecord:
        body_text = state["body"].decode("latin-1", errors="replace")
        preview = body_text[:500]
        rec = EmailRecord(
            timestamp=state["timestamp"],
            sender=state["sender"],
            receiver=state["receiver"],
            subject=state["subject"],
            body_preview=preview,
            attachments=list(state["attachments"]),
            session_id=session_id,
        )
        rec._update_search_str()
        return rec
