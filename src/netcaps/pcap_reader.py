from __future__ import annotations

from pathlib import Path
from typing import Iterator

import dpkt

from .models import PacketRecord


class PcapReadError(Exception):
    pass


def iter_packets(path: str | Path) -> Iterator[PacketRecord]:
    file_path = Path(path)
    if not file_path.exists():
        raise PcapReadError(f"File not found: {file_path}")

    with file_path.open("rb") as f:
        header = f.read(4)
        f.seek(0)
        try:
            if header in {b"\x0a\x0d\x0d\x0a"}:
                reader = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)
        except (ValueError, dpkt.NeedData) as exc:
            raise PcapReadError(f"Unsupported capture format: {file_path}") from exc

        for ts, raw in reader:
            yield PacketRecord(timestamp=float(ts), raw=raw)
