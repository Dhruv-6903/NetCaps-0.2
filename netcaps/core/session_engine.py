"""Session tracking engine for network flows."""

import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import dpkt
except ImportError:
    dpkt = None


_session_counter = 0


def _next_session_id() -> int:
    global _session_counter
    _session_counter += 1
    return _session_counter


@dataclass
class Session:
    session_id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packet_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    tcp_state: str = "UNKNOWN"
    payload_data: List[Tuple[str, bytes]] = field(default_factory=list)
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.src_ip, self.dst_ip,
            str(self.src_port), str(self.dst_port),
            self.protocol, self.tcp_state,
        ]).lower()


_MAX_PAYLOAD_PER_DIR = 64 * 1024  # 64KB


class SessionEngine:
    def __init__(self) -> None:
        self.sessions: Dict[int, Session] = {}
        self._key_to_id: Dict[Tuple, int] = {}
        self._dir_bytes: Dict[int, Dict[str, int]] = {}

    def _normalize_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> Tuple:
        a = (src_ip, src_port, dst_ip, dst_port, protocol)
        b = (dst_ip, dst_port, src_ip, src_port, protocol)
        return min(a, b)

    def _get_or_create_session(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        timestamp: float,
    ) -> Tuple[int, bool]:
        key = self._normalize_key(src_ip, dst_ip, src_port, dst_port, protocol)
        if key in self._key_to_id:
            return self._key_to_id[key], False
        sid = _next_session_id()
        self._key_to_id[key] = sid
        sess = Session(
            session_id=sid,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            start_time=timestamp,
            end_time=timestamp,
        )
        sess._update_search_str()
        self.sessions[sid] = sess
        self._dir_bytes[sid] = {"sent": 0, "recv": 0}
        return sid, True

    def process_packet(self, timestamp: float, eth_frame: bytes) -> Optional[int]:
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

        try:
            src_ip = socket.inet_ntoa(ip.src) if len(ip.src) == 4 else socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntoa(ip.dst) if len(ip.dst) == 4 else socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            return None

        transport = ip.data
        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        payload = b""
        tcp_flags = None

        try:
            if isinstance(transport, dpkt.tcp.TCP):
                protocol = "TCP"
                src_port = transport.sport
                dst_port = transport.dport
                payload = bytes(transport.data)
                tcp_flags = transport.flags
            elif isinstance(transport, dpkt.udp.UDP):
                protocol = "UDP"
                src_port = transport.sport
                dst_port = transport.dport
                payload = bytes(transport.data)
            elif isinstance(transport, dpkt.icmp.ICMP):
                protocol = "ICMP"
            elif isinstance(transport, dpkt.icmp6.ICMP6):
                protocol = "ICMPv6"
        except Exception:
            pass

        sid, is_new = self._get_or_create_session(
            src_ip, dst_ip, src_port, dst_port, protocol, timestamp
        )
        sess = self.sessions[sid]

        # Determine direction
        is_forward = (sess.src_ip == src_ip and sess.src_port == src_port)

        packet_size = len(eth_frame)
        if is_forward:
            sess.bytes_sent += packet_size
        else:
            sess.bytes_recv += packet_size
        sess.packet_count += 1
        sess.end_time = timestamp

        # TCP state tracking
        if protocol == "TCP" and tcp_flags is not None:
            self._update_tcp_state(sess, tcp_flags, is_forward)

        # Payload reassembly
        if payload and protocol in ("TCP", "UDP"):
            direction = "sent" if is_forward else "recv"
            dir_used = self._dir_bytes[sid][direction]
            remaining = _MAX_PAYLOAD_PER_DIR - dir_used
            if remaining > 0:
                chunk = payload[:remaining]
                self._dir_bytes[sid][direction] += len(chunk)
                sess.payload_data.append((direction, chunk))

        sess._update_search_str()
        return sid

    def _update_tcp_state(self, sess: Session, flags: int, is_forward: bool) -> None:
        SYN = 0x02
        ACK = 0x10
        FIN = 0x01
        RST = 0x04

        if flags & RST:
            sess.tcp_state = "CLOSED"
        elif flags & FIN:
            if sess.tcp_state in ("ESTABLISHED", "FIN-WAIT"):
                sess.tcp_state = "FIN-WAIT"
            else:
                sess.tcp_state = "CLOSED"
        elif (flags & SYN) and (flags & ACK):
            sess.tcp_state = "SYN-ACK"
        elif flags & SYN:
            sess.tcp_state = "SYN"
        elif flags & ACK:
            if sess.tcp_state in ("SYN", "SYN-ACK"):
                sess.tcp_state = "ESTABLISHED"
