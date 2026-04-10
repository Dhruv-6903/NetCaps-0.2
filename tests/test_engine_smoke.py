import tempfile
import unittest
from pathlib import Path

try:
    import dpkt
except Exception:  # pragma: no cover
    dpkt = None

from netcaps.engine import ProcessingEngine


@unittest.skipIf(dpkt is None, "dpkt not installed")
class EngineSmokeTests(unittest.TestCase):
    def _make_pcap(self, path: Path) -> None:
        with path.open("wb") as f:
            writer = dpkt.pcap.Writer(f)
            eth = dpkt.ethernet.Ethernet()
            eth.src = b"\x00\x11\x22\x33\x44\x55"
            eth.dst = b"\xaa\xbb\xcc\xdd\xee\xff"
            ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP)
            tcp = dpkt.tcp.TCP(sport=12345, dport=80, flags=dpkt.tcp.TH_SYN, data=b"")
            ip.data = tcp
            ip.len = len(ip)
            eth.data = ip
            writer.writepkt(bytes(eth), ts=1.0)

    def test_engine_process_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pcap = base / "a.pcap"
            self._make_pcap(pcap)
            eng = ProcessingEngine(output_dir=base / "extracted")
            store = eng.process_file(pcap)
            store = eng.finalize()
            self.assertGreaterEqual(len(store.hosts), 2)
            self.assertGreaterEqual(len(store.sessions), 1)


if __name__ == "__main__":
    unittest.main()
