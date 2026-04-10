from __future__ import annotations

import ipaddress
from collections.abc import Callable
from pathlib import Path

import dpkt

from .alerts import AlertEngine
from .artifacts import ArtifactExtractor
from .enrichment import Enrichment
from .models import HostRecord, SessionRecord, TimelineEvent
from .pcap_reader import iter_packets
from .store import CaseStore

ProgressCb = Callable[[CaseStore], None]


class ProcessingEngine:
    def __init__(
        self,
        case_store: CaseStore | None = None,
        output_dir: str | Path = "extracted",
        enrichment: Enrichment | None = None,
        batch_interval_packets: int = 200,
    ) -> None:
        self.store = case_store or CaseStore()
        self.enrichment = enrichment or Enrichment()
        self.extractor = ArtifactExtractor(self.store, Path(output_dir))
        self.alerts = AlertEngine(self.store)
        self.batch_interval_packets = max(10, batch_interval_packets)

    def process_file(self, pcap_path: str | Path, on_batch: ProgressCb | None = None) -> CaseStore:
        for i, pkt in enumerate(iter_packets(pcap_path), start=1):
            try:
                self._process_packet(pkt.timestamp, pkt.raw)
            except Exception:
                continue
            if on_batch and i % self.batch_interval_packets == 0:
                on_batch(self.store)
        if on_batch:
            on_batch(self.store)
        return self.store

    def _host(self, ip: str, ts: float, mac: str | None, packet_len: int) -> HostRecord:
        host = self.store.hosts.get(ip)
        if not host:
            host = HostRecord(ip=ip, mac=mac, first_seen=ts, last_seen=ts)
            host.mac_vendor = self.enrichment.lookup_vendor(mac)
            host.country = self.enrichment.lookup_country(ip)
        host.last_seen = ts
        host.bytes_total += packet_len
        host.packets_total += 1
        self.store.upsert_host(host)
        return host

    @staticmethod
    def _norm_session(
        src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str
    ) -> tuple[tuple[str, str, int, int, str], bool]:
        left = (src_ip, src_port)
        right = (dst_ip, dst_port)
        if left <= right:
            return (src_ip, dst_ip, src_port, dst_port, proto), True
        return (dst_ip, src_ip, dst_port, src_port, proto), False

    def _get_session(
        self, ts: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str
    ) -> tuple[SessionRecord, bool]:
        key, forward = self._norm_session(src_ip, dst_ip, src_port, dst_port, proto)
        sess = self.store.sessions.get(key)
        if not sess:
            sess = SessionRecord(key, key[0], key[1], key[2], key[3], key[4], start_time=ts, end_time=ts)
            self.store.upsert_session(sess)
            self.store.add_timeline(TimelineEvent(ts, "session", f"Session start {key}", {"session_key": key}))
        sess.end_time = ts
        sess.packets_total += 1
        self.store.upsert_session(sess)
        return sess, forward

    def _process_packet(self, ts: float, raw: bytes) -> None:
        eth = dpkt.ethernet.Ethernet(raw)
        mac_src = ":".join(f"{b:02x}" for b in eth.src) if hasattr(eth, "src") else None
        ip = eth.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return
        src_ip = str(ipaddress.ip_address(ip.src))
        dst_ip = str(ipaddress.ip_address(ip.dst))
        self._host(src_ip, ts, mac_src, len(raw))
        self._host(dst_ip, ts, None, len(raw))

        proto_name = "OTHER"
        src_port = dst_port = 0
        payload = b""
        data = ip.data
        if isinstance(data, dpkt.tcp.TCP):
            proto_name = "TCP"
            src_port, dst_port = data.sport, data.dport
            payload = bytes(data.data or b"")
        elif isinstance(data, dpkt.udp.UDP):
            proto_name = "UDP"
            src_port, dst_port = data.sport, data.dport
            payload = bytes(data.data or b"")
        elif isinstance(data, dpkt.icmp.ICMP) or isinstance(data, dpkt.icmp6.ICMP6):
            proto_name = "ICMP"
            self.alerts.observe_icmp(ts, src_ip)
            payload = bytes(data.data or b"")

        sess, forward = self._get_session(ts, src_ip, dst_ip, src_port, dst_port, proto_name)
        if forward:
            sess.bytes_src_to_dst += len(raw)
            direction = "src->dst"
        else:
            sess.bytes_dst_to_src += len(raw)
            direction = "dst->src"
        if proto_name == "TCP":
            sess.tcp_syn_seen = sess.tcp_syn_seen or bool(getattr(data, "flags", 0) & dpkt.tcp.TH_SYN)
            sess.tcp_ack_seen = sess.tcp_ack_seen or bool(getattr(data, "flags", 0) & dpkt.tcp.TH_ACK)
            sess.tcp_fin_seen = sess.tcp_fin_seen or bool(getattr(data, "flags", 0) & dpkt.tcp.TH_FIN)
        if payload:
            sess.stream_chunks.append((ts, direction, payload[:16384]))
        self.store.upsert_session(sess)

        if proto_name == "UDP" and (src_port == 53 or dst_port == 53):
            self.extractor.parse_dns(ts, src_ip, payload, sess.key)
            if self.store.dns and self.store.dns[-1].anomaly_flags:
                for f in self.store.dns[-1].anomaly_flags:
                    self.alerts.observe_dns_anomaly(ts, src_ip, f)
        if proto_name == "TCP":
            if src_port in {80, 8080} or dst_port in {80, 8080}:
                self.extractor.parse_http(ts, payload, sess.key)
            if src_port == 21 or dst_port == 21:
                self.extractor.parse_ftp(ts, payload.decode("utf-8", errors="ignore"), sess.key)
            if src_port in {25, 587} or dst_port in {25, 587}:
                self.extractor.parse_smtp(ts, payload.decode("utf-8", errors="ignore"), sess.key)
            if self.store.credentials:
                self.alerts.observe_credential_exposure(ts, src_ip, sess)

    def finalize(self) -> CaseStore:
        for session in self.store.sessions.values():
            self.alerts.observe_session(session)
            self.store.add_timeline(
                TimelineEvent(session.end_time, "session", f"Session end {session.key}", {"session_key": session.key})
            )
        self.store.timeline.sort(key=lambda e: e.timestamp)
        return self.store
