"""Timeline table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor
    HAS_QT = True
except ImportError:
    HAS_QT = False

_SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff8800",
    "MEDIUM": "#ffdd00",
    "LOW": "#eeffee",
}

if HAS_QT:
    class TimelineModel(BaseTableModel):
        HEADERS = [
            "Time", "Event", "Description", "IP", "Severity",
        ]

        def data(self, index, role=Qt.DisplayRole):
            if not index.isValid():
                return None
            row = self._filtered_rows[index.row()]
            if role == Qt.DisplayRole:
                values = self.row_to_display(row)
                col = index.column()
                if 0 <= col < len(values):
                    return str(values[col]) if values[col] is not None else ""
            elif role == Qt.BackgroundRole:
                severity = getattr(row, "severity", "LOW")
                color = _SEVERITY_COLORS.get(severity)
                if color:
                    return QColor(color)
            return None

        def row_to_display(self, row):
            def fmt_ts(ts):
                try:
                    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    return str(ts)

            return [
                fmt_ts(row.timestamp),
                row.event_type,
                row.description,
                row.related_ip,
                row.severity,
            ]

else:
    class TimelineModel(BaseTableModel):
        HEADERS = [
            "Time", "Event", "Description", "IP", "Severity",
        ]

        def row_to_display(self, row):
            def fmt_ts(ts):
                try:
                    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    return str(ts)

            return [
                fmt_ts(row.timestamp),
                row.event_type,
                row.description,
                row.related_ip,
                row.severity,
            ]
