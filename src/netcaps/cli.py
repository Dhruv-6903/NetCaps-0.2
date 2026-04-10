from __future__ import annotations

import argparse
from pathlib import Path

from .engine import ProcessingEngine
from .exporting import export_csv, export_html_report, export_json, generate_attack_summary
from .ui import run_ui


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NetCaps network forensics")
    p.add_argument("pcap", nargs="?", help="PCAP/PCAPNG input")
    p.add_argument("--extracted-dir", default="extracted")
    p.add_argument("--export-dir", default="exports")
    p.add_argument("--ui", action="store_true", help="Launch desktop UI")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.ui and not args.pcap:
        return run_ui()
    if not args.pcap:
        print("Provide a PCAP path or pass --ui")
        return 1

    engine = ProcessingEngine(output_dir=args.extracted_dir)
    store = engine.process_file(args.pcap)
    store = engine.finalize()
    out = Path(args.export_dir)
    out.mkdir(parents=True, exist_ok=True)
    export_csv(store.alerts, out / "alerts.csv")
    export_csv(store.files, out / "files.csv")
    export_csv(store.credentials, out / "credentials.csv")
    export_json(store, out / "case.json")
    export_html_report(store, out / "report.html")
    (out / "attack_summary.txt").write_text(generate_attack_summary(store), encoding="utf-8")
    print(f"Processed {args.pcap}; exports at {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
