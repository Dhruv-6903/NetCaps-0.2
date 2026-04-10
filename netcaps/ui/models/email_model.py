"""Email records table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel


class EmailModel(BaseTableModel):
    HEADERS = [
        "Time", "Sender", "Receiver", "Subject", "Body Preview",
    ]

    def row_to_display(self, row):
        def fmt_ts(ts):
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(ts)

        return [
            fmt_ts(row.timestamp),
            row.sender,
            row.receiver,
            row.subject,
            row.body_preview[:100],
        ]
