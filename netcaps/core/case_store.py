"""Central case store for all forensic data."""

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class CaseStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.hosts: Dict[str, Any] = {}
        self.sessions: Dict[int, Any] = {}
        self.dns_records: List[Any] = []
        self.files: List[Any] = []
        self.credentials: List[Any] = []
        self.alerts: List[Any] = []
        self.emails: List[Any] = []
        self.timeline: List[Any] = []

        # Indexes
        self.by_domain: Dict[str, List[Any]] = {}
        self.by_filename: Dict[str, List[Any]] = {}
        self.by_username: Dict[str, List[Any]] = {}

    def add_host(self, host: Any) -> None:
        with self._lock:
            self.hosts[host.ip] = host

    def add_session(self, session: Any) -> None:
        with self._lock:
            self.sessions[session.session_id] = session

    def update_session(self, session: Any) -> None:
        with self._lock:
            self.sessions[session.session_id] = session

    def add_dns(self, record: Any) -> None:
        with self._lock:
            self.dns_records.append(record)
            domain = getattr(record, "query", "")
            if domain:
                self.by_domain.setdefault(domain, []).append(record)

    def add_file(self, file_record: Any) -> None:
        with self._lock:
            self.files.append(file_record)
            fname = getattr(file_record, "filename", "")
            if fname:
                self.by_filename.setdefault(fname, []).append(file_record)

    def add_credential(self, cred: Any) -> None:
        with self._lock:
            self.credentials.append(cred)
            username = getattr(cred, "username", "")
            if username:
                self.by_username.setdefault(username, []).append(cred)

    def add_alert(self, alert: Any) -> None:
        with self._lock:
            self.alerts.append(alert)

    def add_email(self, email: Any) -> None:
        with self._lock:
            self.emails.append(email)

    def add_timeline_entry(self, entry: Any) -> None:
        with self._lock:
            self.timeline.append(entry)

    def get_all(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "hosts": list(self.hosts.values()),
                "sessions": list(self.sessions.values()),
                "dns_records": list(self.dns_records),
                "files": list(self.files),
                "credentials": list(self.credentials),
                "alerts": list(self.alerts),
                "emails": list(self.emails),
                "timeline": sorted(self.timeline, key=lambda e: e.timestamp),
            }

    def search(self, query: str) -> Dict[str, List[Any]]:
        query_lower = query.lower()
        words = query_lower.split()

        def _matches(obj: Any) -> bool:
            s = getattr(obj, "search_str", "") or ""
            return all(w in s for w in words)

        with self._lock:
            return {
                "hosts": [h for h in self.hosts.values() if _matches(h)],
                "sessions": [s for s in self.sessions.values() if _matches(s)],
                "dns_records": [r for r in self.dns_records if _matches(r)],
                "files": [f for f in self.files if _matches(f)],
                "credentials": [c for c in self.credentials if _matches(c)],
                "alerts": [a for a in self.alerts if _matches(a)],
                "emails": [e for e in self.emails if _matches(e)],
                "timeline": [t for t in self.timeline if _matches(t)],
            }

    def clear(self) -> None:
        with self._lock:
            self.hosts.clear()
            self.sessions.clear()
            self.dns_records.clear()
            self.files.clear()
            self.credentials.clear()
            self.alerts.clear()
            self.emails.clear()
            self.timeline.clear()
            self.by_domain.clear()
            self.by_filename.clear()
            self.by_username.clear()
