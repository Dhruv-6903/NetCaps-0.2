"""DNS traffic parser and anomaly detector."""

import math
import socket
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Deque, List, Optional, Tuple

try:
    import dpkt
except ImportError:
    dpkt = None


@dataclass
class DNSRecord:
    timestamp: float
    query: str
    qtype: str
    response: str
    status: str
    ttl: int
    src_ip: str
    dst_ip: str
    session_id: int
    is_anomalous: bool = False
    anomaly_reason: str = ""
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.query, self.qtype, self.response, self.status,
            self.src_ip, self.dst_ip, str(self.session_id),
            "anomalous" if self.is_anomalous else "",
            self.anomaly_reason,
        ]).lower()


_QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class DNSParser:
    def __init__(self) -> None:
        self._query_times: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=200))

    def process_packet(
        self,
        timestamp: float,
        eth_frame: bytes,
        session_id: int,
    ) -> Optional[DNSRecord]:
        if dpkt is None:
            return None
        try:
            eth = dpkt.ethernet.Ethernet(eth_frame)
        except Exception:
            return None

        ip = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip = eth.data
        else:
            return None

        if not isinstance(ip.data, dpkt.udp.UDP):
            return None

        udp = ip.data
        if udp.dport != 53 and udp.sport != 53:
            return None

        try:
            src_ip = socket.inet_ntoa(ip.src) if len(ip.src) == 4 else socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntoa(ip.dst) if len(ip.dst) == 4 else socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            return None

        try:
            dns = dpkt.dns.DNS(udp.data)
        except Exception:
            return None

        query_name = ""
        qtype_str = "A"
        if dns.qd:
            q = dns.qd[0]
            query_name = getattr(q, "name", "") or ""
            qtype_str = _QTYPE_MAP.get(getattr(q, "type", 1), "UNKNOWN")

        response_str = ""
        status = "NOERROR"
        ttl = 0
        rcode = getattr(dns, "rcode", 0)

        if rcode == 3:
            status = "NXDOMAIN"
        elif rcode != 0:
            status = f"RCODE-{rcode}"

        if dns.an:
            parts = []
            for rr in dns.an:
                ttl = max(ttl, getattr(rr, "ttl", 0))
                rdata = getattr(rr, "rdata", b"")
                try:
                    if len(rdata) == 4:
                        parts.append(socket.inet_ntoa(rdata))
                    elif len(rdata) == 16:
                        parts.append(socket.inet_ntop(socket.AF_INET6, rdata))
                    else:
                        name = getattr(rr, "name", "")
                        if name:
                            parts.append(name)
                except Exception:
                    pass
            response_str = ", ".join(parts)

        # Anomaly detection
        is_anomalous = False
        anomaly_reason = ""

        if status == "NXDOMAIN":
            is_anomalous = True
            anomaly_reason = "NXDOMAIN response"

        if len(query_name) > 50:
            is_anomalous = True
            anomaly_reason = "Long domain name"

        label = query_name.split(".")[0] if "." in query_name else query_name
        if _entropy(label) > 3.5:
            is_anomalous = True
            anomaly_reason = "High entropy subdomain (possible DGA)"

        # Frequency check
        host_key = src_ip if udp.dport == 53 else dst_ip
        self._query_times[host_key].append(timestamp)
        times = self._query_times[host_key]
        if len(times) >= 10:
            window = [t for t in times if timestamp - t <= 1.0]
            if len(window) > 10:
                is_anomalous = True
                anomaly_reason = "High query frequency (possible DNS flood)"

        record = DNSRecord(
            timestamp=timestamp,
            query=query_name,
            qtype=qtype_str,
            response=response_str,
            status=status,
            ttl=ttl,
            src_ip=src_ip,
            dst_ip=dst_ip,
            session_id=session_id,
            is_anomalous=is_anomalous,
            anomaly_reason=anomaly_reason,
        )
        record._update_search_str()
        return record
