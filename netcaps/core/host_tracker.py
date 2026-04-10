"""Host tracking for observed network participants."""

import socket
from dataclasses import dataclass, field
from typing import Dict, Optional

try:
    import dpkt
except ImportError:
    dpkt = None


_MAC_VENDORS: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:1a:2b": "Cisco",
    "fc:fb:fb": "Cisco",
    "00:50:c2": "IEEE",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "00:1b:21": "Intel",
    "8c:85:90": "Intel",
}

_PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
    ("100.64.0.0", "100.127.255.255"),
]


def _ip_to_int(ip_str: str) -> int:
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return 0
        result = 0
        for p in parts:
            result = (result << 8) | int(p)
        return result
    except Exception:
        return 0


def _is_private(ip_str: str) -> bool:
    ip_int = _ip_to_int(ip_str)
    for start, end in _PRIVATE_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


def _lookup_vendor(mac_str: str) -> str:
    prefix = mac_str[:8].lower()
    return _MAC_VENDORS.get(prefix, "Unknown")


def _get_country(ip_str: str) -> str:
    if _is_private(ip_str):
        return "Private"
    return "Unknown"


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    country: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packet_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    search_str: str = ""

    def _update_search_str(self) -> None:
        self.search_str = " ".join([
            self.ip, self.mac, self.vendor, self.country,
        ]).lower()


class HostTracker:
    def __init__(self) -> None:
        self.hosts: Dict[str, Host] = {}

    def _get_or_create(self, ip: str, mac: str, timestamp: float) -> Host:
        if ip not in self.hosts:
            vendor = _lookup_vendor(mac) if mac else "Unknown"
            country = _get_country(ip)
            host = Host(
                ip=ip,
                mac=mac,
                vendor=vendor,
                country=country,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            host._update_search_str()
            self.hosts[ip] = host
        return self.hosts[ip]

    def _mac_str(self, mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)

    def process_packet(self, timestamp: float, eth_frame: bytes) -> None:
        if dpkt is None:
            return
        try:
            eth = dpkt.ethernet.Ethernet(eth_frame)
        except Exception:
            return

        src_mac = self._mac_str(eth.src)
        dst_mac = self._mac_str(eth.dst)

        ip = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip = eth.data
        else:
            return

        try:
            if len(ip.src) == 4:
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
            else:
                src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            return

        pkt_size = len(eth_frame)

        src_host = self._get_or_create(src_ip, src_mac, timestamp)
        src_host.bytes_sent += pkt_size
        src_host.packet_count += 1
        src_host.last_seen = timestamp
        src_host._update_search_str()

        dst_host = self._get_or_create(dst_ip, dst_mac, timestamp)
        dst_host.bytes_recv += pkt_size
        dst_host.packet_count += 1
        dst_host.last_seen = timestamp
        dst_host._update_search_str()
