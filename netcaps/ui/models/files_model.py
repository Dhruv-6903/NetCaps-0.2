"""Files table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel


class FilesModel(BaseTableModel):
    HEADERS = [
        "Time", "Filename", "Type", "Size", "MD5", "SHA256", "Session",
    ]

    def row_to_display(self, row):
        def fmt_ts(ts):
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(ts)

        return [
            fmt_ts(row.timestamp),
            row.filename,
            getattr(row, "file_type", getattr(row, "content_type", "")),
            f"{row.size:,}",
            row.md5,
            row.sha256,
            str(row.session_id),
        ]
