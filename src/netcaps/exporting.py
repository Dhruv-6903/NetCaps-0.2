from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

from .store import CaseStore


def _to_dict(item: Any) -> dict[str, Any]:
    if is_dataclass(item):
        return asdict(item)
    if isinstance(item, dict):
        return item
    return vars(item)


def export_csv(rows: Iterable[Any], path: str | Path) -> None:
    rows = list(rows)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        p.write_text("", encoding="utf-8")
        return
    data = [_to_dict(r) for r in rows]
    headers = sorted({k for row in data for k in row.keys()})
    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in data:
            writer.writerow(row)


def export_json(store: CaseStore, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(store.to_jsonable(), indent=2), encoding="utf-8")


def export_html_report(store: CaseStore, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    top_hosts = sorted(store.hosts.values(), key=lambda h: h.bytes_total, reverse=True)[:10]
    alerts = sorted(store.alerts, key=lambda a: a.timestamp, reverse=True)[:25]
    body = [
        "<html><head><meta charset='utf-8'><title>NetCaps Report</title></head><body>",
        "<h1>NetCaps Case Report</h1>",
        f"<p>Hosts: {len(store.hosts)} | Sessions: {len(store.sessions)} | Alerts: {len(store.alerts)}</p>",
        "<h2>Top Hosts</h2><ul>",
    ]
    body.extend(f"<li>{html.escape(h.ip)} bytes={h.bytes_total} packets={h.packets_total}</li>" for h in top_hosts)
    body.append("</ul><h2>Alerts</h2><ul>")
    body.extend(
        f"<li>[{html.escape(a.severity)}] {html.escape(a.rule)}: {html.escape(a.message)}</li>"
        for a in alerts
    )
    body.append("</ul></body></html>")
    p.write_text("\n".join(body), encoding="utf-8")


def generate_attack_summary(store: CaseStore) -> str:
    lines: list[str] = []
    if store.alerts:
        lines.append(f"Detected {len(store.alerts)} alerts.")
    if store.credentials:
        lines.append(f"Recovered {len(store.credentials)} credentials from captured traffic.")
    if store.files:
        lines.append(f"Extracted {len(store.files)} files.")
    if store.dns:
        nx = sum(1 for d in store.dns if "NXDOMAIN_SPIKE" in d.anomaly_flags)
        if nx:
            lines.append(f"Observed {nx} DNS anomalies related to NXDOMAIN activity.")
    if not lines:
        lines.append("No significant malicious indicators were detected in this capture.")
    return " ".join(lines)
