"""Timeline engine for forensic event tracking."""

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from netcaps.core.case_store import CaseStore


EVENT_DNS_QUERY = "DNS_QUERY"
EVENT_SESSION_START = "SESSION_START"
EVENT_SESSION_END = "SESSION_END"
EVENT_FILE_EXTRACTED = "FILE_EXTRACTED"
EVENT_CREDENTIAL_FOUND = "CREDENTIAL_FOUND"
EVENT_ALERT_TRIGGERED = "ALERT_TRIGGERED"
EVENT_EMAIL_FOUND = "EMAIL_FOUND"


@dataclass
class TimelineEntry:
    timestamp: float
    event_type: str
    description: str
    related_ip: str = ""
    related_session: int = 0
    severity: str = "LOW"
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.event_type,
            self.description,
            self.related_ip,
            str(self.related_session),
            self.severity,
        ]).lower()


class TimelineEngine:
    def __init__(self, case_store: "CaseStore") -> None:
        self._store = case_store

    def add_event(
        self,
        event_type: str,
        description: str,
        timestamp: float,
        related_ip: str = "",
        related_session: int = 0,
        severity: str = "LOW",
    ) -> None:
        entry = TimelineEntry(
            timestamp=timestamp,
            event_type=event_type,
            description=description,
            related_ip=related_ip,
            related_session=related_session,
            severity=severity,
        )
        entry._update_search_str()
        self._store.add_timeline_entry(entry)
