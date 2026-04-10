from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, is_dataclass
from typing import Any, Iterable

from .models import (
    AlertRecord,
    CredentialRecord,
    DNSRecord,
    EmailRecord,
    FileRecord,
    HostRecord,
    SessionRecord,
    TimelineEvent,
)


class CaseStore:
    def __init__(self, max_events: int = 500000) -> None:
        self.max_events = max_events
        self.hosts: dict[str, HostRecord] = {}
        self.sessions: dict[tuple[str, str, int, int, str], SessionRecord] = {}
        self.dns: list[DNSRecord] = []
        self.files: list[FileRecord] = []
        self.credentials: list[CredentialRecord] = []
        self.alerts: list[AlertRecord] = []
        self.email: list[EmailRecord] = []
        self.timeline: list[TimelineEvent] = []

        self.index_ip: dict[str, set[int]] = defaultdict(set)
        self.index_domain_substring: dict[str, set[int]] = defaultdict(set)
        self.index_filename: dict[str, set[int]] = defaultdict(set)
        self.index_username: dict[str, set[int]] = defaultdict(set)

        self.search_rows: dict[str, list[str]] = defaultdict(list)

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        t = "".join(c if c.isalnum() else " " for c in text.lower())
        tokens = {tok for tok in t.split() if tok}
        out = set(tokens)
        for token in tokens:
            for i in range(1, len(token) + 1):
                out.add(token[:i])
        return out

    def _flatten(self, item: Any) -> str:
        if is_dataclass(item):
            item = asdict(item)
        if isinstance(item, dict):
            return " ".join(self._flatten(v) for v in item.values())
        if isinstance(item, (list, tuple, set)):
            return " ".join(self._flatten(v) for v in item)
        return str(item)

    def _add_search_row(self, tab: str, item: Any) -> None:
        self.search_rows[tab].append(self._flatten(item).lower())

    def add_timeline(self, event: TimelineEvent) -> None:
        if len(self.timeline) >= self.max_events:
            self.timeline.pop(0)
            if self.search_rows.get("timeline"):
                self.search_rows["timeline"].pop(0)
        self.timeline.append(event)
        self._add_search_row("timeline", event)

    def upsert_host(self, host: HostRecord) -> None:
        self.hosts[host.ip] = host
        self.index_ip[host.ip].add(len(self.hosts) - 1)

    def upsert_session(self, session: SessionRecord) -> None:
        self.sessions[session.key] = session

    def add_dns(self, rec: DNSRecord) -> None:
        if len(self.dns) >= self.max_events:
            return
        idx = len(self.dns)
        self.dns.append(rec)
        self.index_ip[rec.src_ip].add(idx)
        self._add_search_row("dns", rec)
        for token in self._tokenize(rec.query):
            self.index_domain_substring[token].add(idx)

    def add_file(self, rec: FileRecord) -> None:
        if len(self.files) >= self.max_events:
            return
        idx = len(self.files)
        self.files.append(rec)
        self._add_search_row("files", rec)
        for token in self._tokenize(rec.filename):
            self.index_filename[token].add(idx)

    def add_credential(self, rec: CredentialRecord) -> None:
        if len(self.credentials) >= self.max_events:
            return
        idx = len(self.credentials)
        self.credentials.append(rec)
        self._add_search_row("credentials", rec)
        for token in self._tokenize(rec.username):
            self.index_username[token].add(idx)

    def add_alert(self, rec: AlertRecord) -> None:
        if len(self.alerts) >= self.max_events:
            return
        self.alerts.append(rec)
        self._add_search_row("alerts", rec)

    def add_email(self, rec: EmailRecord) -> None:
        if len(self.email) >= self.max_events:
            return
        self.email.append(rec)
        self._add_search_row("email", rec)

    def filter_rows(self, tab: str, query: str) -> list[int]:
        q = query.strip().lower()
        if not q:
            return list(range(len(self.search_rows.get(tab, []))))
        return [i for i, row in enumerate(self.search_rows.get(tab, [])) if q in row]

    def global_filter(self, query: str) -> dict[str, list[int]]:
        q = query.strip().lower()
        out: dict[str, list[int]] = {}
        for tab in self.search_rows:
            out[tab] = self.filter_rows(tab, q)
        return out

    def to_jsonable(self) -> dict[str, Any]:
        def conv(items: Iterable[Any]) -> list[dict[str, Any]]:
            return [asdict(i) if is_dataclass(i) else dict(i) for i in items]

        return {
            "hosts": conv(self.hosts.values()),
            "sessions": conv(self.sessions.values()),
            "dns": conv(self.dns),
            "files": conv(self.files),
            "credentials": conv(self.credentials),
            "alerts": conv(self.alerts),
            "email": conv(self.email),
            "timeline": conv(self.timeline),
        }
