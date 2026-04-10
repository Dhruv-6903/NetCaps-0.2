"""Alert engine for network anomaly detection."""

import socket
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from netcaps.core.case_store import CaseStore

try:
    import dpkt
except ImportError:
    dpkt = None


SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


@dataclass
class AlertRecord:
    timestamp: float
    alert_type: str
    severity: str
    description: str
    src_ip: str
    dst_ip: str
    session_id: int
    related_data: str = ""
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.alert_type, self.severity, self.description,
            self.src_ip, self.dst_ip, str(self.session_id),
            self.related_data,
        ]).lower()


class AlertEngine:
    def __init__(self) -> None:
        # Port scan tracking: src_ip -> deque of (timestamp, dst_port)
        self._port_scan: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # ICMP flood: src_ip -> deque of timestamps
        self._icmp_flood: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # Brute force: (src_ip, dst_ip) -> deque of (timestamp, success)
        self._brute_force: Dict[Tuple[str, str], Deque[float]] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._generated_alerts: Dict[str, float] = {}

    def _dedup_key(self, alert_type: str, src_ip: str, dst_ip: str) -> str:
        return f"{alert_type}:{src_ip}:{dst_ip}"

    def _should_emit(self, key: str, timestamp: float, cooldown: float = 30.0) -> bool:
        last = self._generated_alerts.get(key, 0.0)
        if timestamp - last > cooldown:
            self._generated_alerts[key] = timestamp
            return True
        return False

    def check_port_scan(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        session_id: int,
    ) -> Optional[AlertRecord]:
        window = self._port_scan[src_ip]
        window.append((timestamp, dst_port))

        recent = [(t, p) for t, p in window if timestamp - t <= 60.0]
        unique_ports = len({p for _, p in recent})

        if unique_ports > 20:
            key = self._dedup_key("PORT_SCAN", src_ip, dst_ip)
            if self._should_emit(key, timestamp):
                alert = AlertRecord(
                    timestamp=timestamp,
                    alert_type="PORT_SCAN",
                    severity=SEVERITY_HIGH,
                    description=f"Port scan detected: {src_ip} scanned {unique_ports} ports in 60s",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    session_id=session_id,
                    related_data=f"unique_ports={unique_ports}",
                )
                alert._update_search_str()
                return alert
        return None

    def check_large_transfer(
        self,
        session: Any,
    ) -> Optional[AlertRecord]:
        total = session.bytes_sent + session.bytes_recv
        if total > 100 * 1024 * 1024:  # 100MB
            key = self._dedup_key("LARGE_TRANSFER", session.src_ip, session.dst_ip)
            if self._should_emit(key, session.end_time, cooldown=120.0):
                alert = AlertRecord(
                    timestamp=session.end_time,
                    alert_type="LARGE_TRANSFER",
                    severity=SEVERITY_MEDIUM,
                    description=f"Large transfer detected: {total // (1024*1024)}MB in session {session.session_id}",
                    src_ip=session.src_ip,
                    dst_ip=session.dst_ip,
                    session_id=session.session_id,
                    related_data=f"bytes={total}",
                )
                alert._update_search_str()
                return alert
        return None

    def check_dns_anomaly(
        self,
        dns_record: Any,
    ) -> Optional[AlertRecord]:
        if dns_record.is_anomalous:
            key = self._dedup_key("SUSPICIOUS_DNS", dns_record.src_ip, dns_record.dst_ip)
            if self._should_emit(key, dns_record.timestamp, cooldown=10.0):
                alert = AlertRecord(
                    timestamp=dns_record.timestamp,
                    alert_type="SUSPICIOUS_DNS",
                    severity=SEVERITY_MEDIUM,
                    description=f"Suspicious DNS: {dns_record.query} - {dns_record.anomaly_reason}",
                    src_ip=dns_record.src_ip,
                    dst_ip=dns_record.dst_ip,
                    session_id=dns_record.session_id,
                    related_data=dns_record.anomaly_reason,
                )
                alert._update_search_str()
                return alert
        return None

    def check_credential_exposure(
        self,
        cred: Any,
        timestamp: float,
    ) -> Optional[AlertRecord]:
        src_ip = getattr(cred, "client_ip", "") or ""
        dst_ip = getattr(cred, "server_ip", "") or getattr(cred, "host", "") or ""
        sid = getattr(cred, "session_id", 0)
        key = self._dedup_key("CREDENTIAL_EXPOSURE", src_ip, dst_ip)
        if self._should_emit(key, timestamp, cooldown=5.0):
            alert = AlertRecord(
                timestamp=timestamp,
                alert_type="CREDENTIAL_EXPOSURE",
                severity=SEVERITY_HIGH,
                description=f"Plaintext credential found: user={getattr(cred, 'username', '')}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                session_id=sid,
                related_data=f"username={getattr(cred, 'username', '')}",
            )
            alert._update_search_str()
            return alert
        return None

    def check_icmp_flood(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        session_id: int,
    ) -> Optional[AlertRecord]:
        window = self._icmp_flood[src_ip]
        window.append(timestamp)
        recent = [t for t in window if timestamp - t <= 10.0]
        if len(recent) > 100:
            key = self._dedup_key("ICMP_FLOOD", src_ip, dst_ip)
            if self._should_emit(key, timestamp):
                alert = AlertRecord(
                    timestamp=timestamp,
                    alert_type="ICMP_FLOOD",
                    severity=SEVERITY_MEDIUM,
                    description=f"ICMP flood detected: {src_ip} sent {len(recent)} packets in 10s",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    session_id=session_id,
                    related_data=f"count={len(recent)}",
                )
                alert._update_search_str()
                return alert
        return None

    def process_packet(
        self,
        timestamp: float,
        eth_frame: bytes,
        session_id: int,
    ) -> List[AlertRecord]:
        if dpkt is None:
            return []

        alerts: List[AlertRecord] = []
        try:
            eth = dpkt.ethernet.Ethernet(eth_frame)
        except Exception:
            return alerts

        ip = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip = eth.data
        else:
            return alerts

        try:
            src_ip = socket.inet_ntoa(ip.src) if len(ip.src) == 4 else socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntoa(ip.dst) if len(ip.dst) == 4 else socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            return alerts

        transport = ip.data

        try:
            if isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                alert = self.check_icmp_flood(timestamp, src_ip, dst_ip, session_id)
                if alert:
                    alerts.append(alert)
            elif isinstance(transport, dpkt.tcp.TCP):
                alert = self.check_port_scan(timestamp, src_ip, dst_ip, transport.dport, session_id)
                if alert:
                    alerts.append(alert)
        except Exception:
            pass

        return alerts
