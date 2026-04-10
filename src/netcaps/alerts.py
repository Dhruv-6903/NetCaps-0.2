from __future__ import annotations

from collections import Counter, defaultdict

from .models import AlertRecord, SessionRecord, TimelineEvent
from .store import CaseStore


class AlertEngine:
    def __init__(self, store: CaseStore) -> None:
        self.store = store
        self.port_targets: dict[str, set[int]] = defaultdict(set)
        self.failed_auth: Counter[str] = Counter()
        self.icmp_counter: Counter[str] = Counter()

    def observe_session(self, session: SessionRecord) -> None:
        self.port_targets[session.src_ip].add(session.dst_port)
        if len(self.port_targets[session.src_ip]) > 25:
            self._alert(session.end_time, "PORT_SCAN", "high", f"Port scan from {session.src_ip}", session)
        if (session.bytes_src_to_dst + session.bytes_dst_to_src) > 50 * 1024 * 1024:
            self._alert(session.end_time, "LARGE_TRANSFER", "medium", "Large data transfer observed", session)

    def observe_failed_auth(self, ts: float, host_ip: str) -> None:
        self.failed_auth[host_ip] += 1
        if self.failed_auth[host_ip] >= 5:
            self._alert(ts, "BRUTE_FORCE", "high", f"Repeated auth failures from {host_ip}", None, host_ip)

    def observe_dns_anomaly(self, ts: float, host_ip: str, label: str) -> None:
        self._alert(ts, "SUSPICIOUS_DNS", "medium", f"{label} by {host_ip}", None, host_ip)

    def observe_credential_exposure(self, ts: float, host_ip: str, session: SessionRecord | None = None) -> None:
        self._alert(ts, "CREDENTIAL_EXPOSURE", "high", f"Credential exposure near {host_ip}", session, host_ip)

    def observe_icmp(self, ts: float, src_ip: str, session: SessionRecord | None = None) -> None:
        self.icmp_counter[src_ip] += 1
        if self.icmp_counter[src_ip] > 200:
            self._alert(ts, "ICMP_FLOOD", "high", f"Potential ICMP flood from {src_ip}", session, src_ip)

    def _alert(
        self,
        ts: float,
        rule: str,
        severity: str,
        message: str,
        session: SessionRecord | None,
        host_ip: str | None = None,
    ) -> None:
        rec = AlertRecord(ts, rule, severity, message, host_ip=host_ip, session_key=session.key if session else None)
        self.store.add_alert(rec)
        self.store.add_timeline(TimelineEvent(ts, "alert", f"[{severity}] {rule}: {message}", {}))
