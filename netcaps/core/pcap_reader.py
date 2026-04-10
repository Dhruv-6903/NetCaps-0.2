"""PCAP file reader supporting PCAP and PCAPNG formats."""

import struct
from typing import Generator, Tuple


PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NS = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _detect_format(filepath: str) -> str:
    with open(filepath, "rb") as f:
        magic = f.read(4)
    if magic in (PCAP_MAGIC, PCAP_MAGIC_NS, b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return "pcap"


def read_pcap(filepath: str) -> Generator[Tuple[float, bytes], None, None]:
    """Yield (timestamp, raw_bytes) tuples from a PCAP or PCAPNG file."""
    import dpkt

    fmt = _detect_format(filepath)

    if fmt == "pcapng":
        try:
            with open(filepath, "rb") as f:
                scanner = dpkt.pcapng.Scanner(f)
                for ts, buf in scanner:
                    try:
                        yield float(ts), bytes(buf)
                    except Exception:
                        continue
            return
        except Exception:
            pass

    try:
        with open(filepath, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            for ts, buf in reader:
                try:
                    yield float(ts), bytes(buf)
                except Exception:
                    continue
    except Exception:
        try:
            with open(filepath, "rb") as f:
                scanner = dpkt.pcapng.Scanner(f)
                for ts, buf in scanner:
                    try:
                        yield float(ts), bytes(buf)
                    except Exception:
                        continue
        except Exception:
            return
