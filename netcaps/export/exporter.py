"""Export functionality for case data."""

import csv
import datetime
import json
import os
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from netcaps.core.case_store import CaseStore


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def _safe(val: Any) -> str:
    if val is None:
        return ""
    return str(val)


class Exporter:
    def export_csv(self, data: List[Any], filepath: str, tab_name: str) -> None:
        """Export a list of dataclass records to CSV."""
        if not data:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                f.write("")
            return

        row0 = data[0]
        fields = [f for f in vars(row0).keys() if f != "search_str"]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(fields)
            for item in data:
                writer.writerow([_safe(getattr(item, field, "")) for field in fields])

    def export_json(self, case_store: "CaseStore", filepath: str) -> None:
        """Export full case data as JSON."""
        all_data = case_store.get_all()
        output: Dict[str, Any] = {}

        for key, items in all_data.items():
            serialized = []
            for item in items:
                d = {}
                for field, val in vars(item).items():
                    if field == "search_str":
                        continue
                    if field == "payload_data":
                        d[field] = f"[{len(val)} chunks]"
                    elif isinstance(val, (list, bytes)):
                        d[field] = str(val)
                    else:
                        d[field] = val
                serialized.append(d)
            output[key] = serialized

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

    def export_html(self, case_store: "CaseStore", filepath: str) -> None:
        """Export HTML forensics report."""
        all_data = case_store.get_all()
        hosts = all_data["hosts"]
        sessions = all_data["sessions"]
        alerts = all_data["alerts"]
        timeline = all_data["timeline"]

        summary = self.generate_attack_summary(case_store)

        html_parts = [
            "<!DOCTYPE html><html><head>",
            "<meta charset='UTF-8'>",
            "<title>NetCaps Forensic Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "h1 { color: #333; }",
            "h2 { color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }",
            "table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }",
            "th { background: #4e79a7; color: white; padding: 8px; text-align: left; }",
            "td { padding: 6px 8px; border-bottom: 1px solid #ddd; }",
            "tr:nth-child(even) { background: #f5f5f5; }",
            ".severity-CRITICAL { background: #ff4444; color: white; }",
            ".severity-HIGH { background: #ff8800; color: white; }",
            ".severity-MEDIUM { background: #ffdd00; }",
            ".severity-LOW { background: #88cc44; }",
            ".summary-box { background: #f0f4fa; border: 1px solid #c0d0e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }",
            "</style></head><body>",
            f"<h1>NetCaps Forensic Report</h1>",
            f"<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "<div class='summary-box'>",
            "<h2>Executive Summary</h2>",
            f"<p>{summary}</p>",
            f"<ul><li>Total Hosts: {len(hosts)}</li>",
            f"<li>Total Sessions: {len(sessions)}</li>",
            f"<li>Total Alerts: {len(alerts)}</li>",
            f"<li>Timeline Events: {len(timeline)}</li></ul>",
            "</div>",
        ]

        # Top Alerts
        html_parts.append("<h2>Top Alerts</h2>")
        html_parts.append("<table><tr><th>Time</th><th>Type</th><th>Severity</th><th>Description</th><th>Src IP</th><th>Dst IP</th></tr>")
        for alert in sorted(alerts, key=lambda a: a.severity)[:50]:
            sev_class = f"severity-{alert.severity}"
            html_parts.append(
                f"<tr class='{sev_class}'>"
                f"<td>{_fmt_ts(alert.timestamp)}</td>"
                f"<td>{_safe(alert.alert_type)}</td>"
                f"<td>{_safe(alert.severity)}</td>"
                f"<td>{_safe(alert.description)}</td>"
                f"<td>{_safe(alert.src_ip)}</td>"
                f"<td>{_safe(alert.dst_ip)}</td></tr>"
            )
        html_parts.append("</table>")

        # Top Hosts
        html_parts.append("<h2>Top Hosts by Traffic</h2>")
        html_parts.append("<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Country</th><th>Bytes Sent</th><th>Bytes Recv</th><th>Packets</th></tr>")
        for host in sorted(hosts, key=lambda h: -(h.bytes_sent + h.bytes_recv))[:20]:
            html_parts.append(
                f"<tr><td>{host.ip}</td><td>{host.mac}</td><td>{host.vendor}</td>"
                f"<td>{host.country}</td><td>{host.bytes_sent:,}</td>"
                f"<td>{host.bytes_recv:,}</td><td>{host.packet_count:,}</td></tr>"
            )
        html_parts.append("</table>")

        # Timeline
        html_parts.append("<h2>Timeline</h2>")
        html_parts.append("<table><tr><th>Time</th><th>Event</th><th>Description</th><th>IP</th><th>Severity</th></tr>")
        for entry in timeline[:200]:
            sev_class = f"severity-{entry.severity}"
            html_parts.append(
                f"<tr><td>{_fmt_ts(entry.timestamp)}</td>"
                f"<td>{_safe(entry.event_type)}</td>"
                f"<td>{_safe(entry.description)}</td>"
                f"<td>{_safe(entry.related_ip)}</td>"
                f"<td class='{sev_class}'>{_safe(entry.severity)}</td></tr>"
            )
        html_parts.append("</table>")
        html_parts.append("</body></html>")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))

    def generate_attack_summary(self, case_store: "CaseStore") -> str:
        all_data = case_store.get_all()
        hosts = all_data["hosts"]
        sessions = all_data["sessions"]
        alerts = all_data["alerts"]
        creds = all_data["credentials"]
        dns = all_data["dns_records"]
        files = all_data["files"]
        emails = all_data["emails"]

        n_hosts = len(hosts)
        n_sessions = len(sessions)
        n_alerts = len(alerts)
        n_creds = len(creds)
        n_dns = len(dns)
        n_files = len(files)
        n_emails = len(emails)

        critical = [a for a in alerts if a.severity == "CRITICAL"]
        high = [a for a in alerts if a.severity == "HIGH"]
        medium = [a for a in alerts if a.severity == "MEDIUM"]

        anomalous_dns = [r for r in dns if r.is_anomalous]

        summary_parts = [
            f"Analysis identified {n_hosts} unique hosts across {n_sessions} network sessions.",
        ]

        if n_alerts:
            summary_parts.append(
                f"A total of {n_alerts} security alerts were generated "
                f"({len(critical)} CRITICAL, {len(high)} HIGH, {len(medium)} MEDIUM)."
            )

        if n_creds:
            summary_parts.append(
                f"{n_creds} plaintext credential(s) were captured, indicating insecure protocol usage."
            )

        if anomalous_dns:
            summary_parts.append(
                f"{len(anomalous_dns)} suspicious DNS queries detected (possible DGA or NXDOMAIN flooding)."
            )

        if n_files:
            summary_parts.append(f"{n_files} file(s) were extracted from HTTP traffic.")

        if n_emails:
            summary_parts.append(f"{n_emails} email message(s) were recovered from SMTP traffic.")

        types = set(a.alert_type for a in alerts)
        if "PORT_SCAN" in types:
            summary_parts.append("Port scanning activity was detected.")
        if "ICMP_FLOOD" in types:
            summary_parts.append("ICMP flooding was observed.")
        if "LARGE_TRANSFER" in types:
            summary_parts.append("Unusually large data transfers (>100MB) were identified.")

        if not n_alerts:
            summary_parts.append("No significant security anomalies were detected.")

        return " ".join(summary_parts)
