"""Credentials table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel


class CredentialsModel(BaseTableModel):
    HEADERS = [
        "Time", "Username", "Password", "Method", "Host", "Session",
    ]

    def row_to_display(self, row):
        def fmt_ts(ts):
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(ts)

        host = getattr(row, "host", "") or getattr(row, "server_ip", "") or ""
        method = getattr(row, "method", "") or "FTP"
        return [
            fmt_ts(row.timestamp),
            row.username,
            row.password,
            method,
            host,
            str(row.session_id),
        ]
