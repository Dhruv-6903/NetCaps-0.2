"""DNS records table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel


class DNSModel(BaseTableModel):
    HEADERS = [
        "Time", "Query", "Type", "Response", "Status", "Src IP", "Anomaly",
    ]

    def row_to_display(self, row):
        def fmt_ts(ts):
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(ts)

        anomaly_str = row.anomaly_reason if row.is_anomalous else ""
        return [
            fmt_ts(row.timestamp),
            row.query,
            row.qtype,
            row.response,
            row.status,
            row.src_ip,
            anomaly_str,
        ]
