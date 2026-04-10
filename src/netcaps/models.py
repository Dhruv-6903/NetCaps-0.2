from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PacketRecord:
    timestamp: float
    raw: bytes


@dataclass(slots=True)
class HostRecord:
    ip: str
    mac: str | None = None
    bytes_total: int = 0
    packets_total: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    mac_vendor: str | None = None
    country: str | None = None


@dataclass(slots=True)
class SessionRecord:
    key: tuple[str, str, int, int, str]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    packets_total: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    tcp_syn_seen: bool = False
    tcp_ack_seen: bool = False
    tcp_fin_seen: bool = False
    stream_chunks: list[tuple[float, str, bytes]] = field(default_factory=list)


@dataclass(slots=True)
class DNSRecord:
    timestamp: float
    src_ip: str
    query: str
    qtype: str
    status: str
    answers: list[str] = field(default_factory=list)
    anomaly_flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FileRecord:
    timestamp: float
    source: str
    filename: str
    content_type: str | None
    size: int
    md5: str
    sha256: str
    path: str
    session_key: tuple[str, str, int, int, str] | None = None
    vt_status: str = "pending"
    vt_result: str | None = None


@dataclass(slots=True)
class CredentialRecord:
    timestamp: float
    protocol: str
    username: str
    password: str
    source: str
    session_key: tuple[str, str, int, int, str] | None = None


@dataclass(slots=True)
class AlertRecord:
    timestamp: float
    rule: str
    severity: str
    message: str
    host_ip: str | None = None
    session_key: tuple[str, str, int, int, str] | None = None


@dataclass(slots=True)
class EmailRecord:
    timestamp: float
    sender: str | None
    receiver: str | None
    subject: str | None
    body_preview: str
    attachments: list[str] = field(default_factory=list)
    session_key: tuple[str, str, int, int, str] | None = None


@dataclass(slots=True)
class TimelineEvent:
    timestamp: float
    category: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
