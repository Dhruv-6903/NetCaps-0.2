"""Visualization widget using QPainter for traffic charts."""

import datetime
from typing import Dict, List, Tuple

try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QTabWidget
    from PySide6.QtCore import Qt, QRect, QPoint, QSize
    from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QPainterPath
    HAS_QT = True
except ImportError:
    HAS_QT = False

_COLORS = [
    QColor("#4e79a7"), QColor("#f28e2b"), QColor("#e15759"),
    QColor("#76b7b2"), QColor("#59a14f"), QColor("#edc948"),
    QColor("#b07aa1"), QColor("#ff9da7"), QColor("#9c755f"),
    QColor("#bab0ac"),
] if HAS_QT else []


if HAS_QT:
    class TrafficBarChart(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._data: List[Tuple[str, int]] = []
            self.setMinimumHeight(200)

        def setData(self, data: List[Tuple[str, int]]) -> None:
            self._data = data
            self.update()

        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            w, h = self.width(), self.height()
            margin = 50

            painter.fillRect(0, 0, w, h, QColor("#f8f8f8"))

            if not self._data:
                painter.drawText(w // 2 - 60, h // 2, "No data available")
                return

            max_val = max(v for _, v in self._data) or 1
            n = len(self._data)
            chart_w = w - 2 * margin
            chart_h = h - 2 * margin
            bar_w = max(4, chart_w // n - 2)

            painter.setPen(QPen(Qt.black, 1))
            painter.drawLine(margin, margin, margin, h - margin)
            painter.drawLine(margin, h - margin, w - margin, h - margin)

            font = QFont("Arial", 7)
            painter.setFont(font)

            for i, (label, val) in enumerate(self._data):
                x = margin + i * (chart_w // n) + 2
                bar_h = int((val / max_val) * chart_h)
                y = h - margin - bar_h
                color = _COLORS[i % len(_COLORS)]
                painter.fillRect(x, y, bar_w, bar_h, color)
                painter.setPen(QPen(Qt.black, 1))
                # Rotated label
                painter.save()
                painter.translate(x + bar_w // 2, h - margin + 2)
                painter.rotate(-45)
                painter.drawText(0, 0, label[:8])
                painter.restore()

    class PieChart(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._data: List[Tuple[str, int]] = []
            self.setMinimumHeight(200)

        def setData(self, data: List[Tuple[str, int]]) -> None:
            self._data = data
            self.update()

        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            w, h = self.width(), self.height()

            painter.fillRect(0, 0, w, h, QColor("#f8f8f8"))

            if not self._data:
                painter.drawText(w // 2 - 60, h // 2, "No data available")
                return

            total = sum(v for _, v in self._data) or 1
            cx = w // 3
            cy = h // 2
            radius = min(cx, cy) - 20

            start_angle = 0
            font = QFont("Arial", 8)
            painter.setFont(font)

            legend_x = cx * 2 + 10
            legend_y = 20

            for i, (label, val) in enumerate(self._data):
                span = int((val / total) * 360 * 16)
                color = _COLORS[i % len(_COLORS)]
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(Qt.white, 1))
                painter.drawPie(cx - radius, cy - radius, radius * 2, radius * 2, start_angle, span)
                start_angle += span

                # Legend
                painter.fillRect(legend_x, legend_y + i * 18, 12, 12, color)
                painter.setPen(QPen(Qt.black, 1))
                pct = (val / total) * 100
                painter.drawText(legend_x + 16, legend_y + i * 18 + 10, f"{label}: {pct:.1f}%")

    class HBarChart(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._data: List[Tuple[str, int]] = []
            self.setMinimumHeight(220)

        def setData(self, data: List[Tuple[str, int]]) -> None:
            self._data = data[:10]
            self.update()

        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            w, h = self.width(), self.height()
            margin_left = 130
            margin_right = 20
            margin_top = 20
            margin_bot = 10

            painter.fillRect(0, 0, w, h, QColor("#f8f8f8"))

            if not self._data:
                painter.drawText(w // 2 - 60, h // 2, "No data available")
                return

            max_val = max(v for _, v in self._data) or 1
            n = len(self._data)
            chart_h = h - margin_top - margin_bot
            bar_h = max(8, chart_h // n - 4)
            chart_w = w - margin_left - margin_right

            font = QFont("Arial", 8)
            painter.setFont(font)

            for i, (label, val) in enumerate(self._data):
                y = margin_top + i * (chart_h // n)
                bar_w = int((val / max_val) * chart_w)
                color = _COLORS[i % len(_COLORS)]
                painter.fillRect(margin_left, y, bar_w, bar_h, color)
                painter.setPen(QPen(Qt.black, 1))
                painter.drawText(2, y + bar_h - 2, label[:18])
                painter.drawText(margin_left + bar_w + 4, y + bar_h - 2, _fmt_bytes(val))

    def _fmt_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f}{unit}"
            n //= 1024
        return f"{n:.0f}TB"

    class VisualizationWidget(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            layout = QVBoxLayout(self)
            tabs = QTabWidget()
            layout.addWidget(tabs)

            self._traffic_chart = TrafficBarChart()
            tabs.addTab(self._traffic_chart, "Traffic Over Time")

            self._proto_chart = PieChart()
            tabs.addTab(self._proto_chart, "Protocol Distribution")

            self._top_ips_chart = HBarChart()
            tabs.addTab(self._top_ips_chart, "Top 10 IPs by Traffic")

        def update_data(self, case_data: dict) -> None:
            self._update_traffic(case_data)
            self._update_protocols(case_data)
            self._update_top_ips(case_data)

        def _update_traffic(self, case_data: dict) -> None:
            sessions = case_data.get("sessions", [])
            buckets: Dict[str, int] = {}
            for sess in sessions:
                try:
                    dt = datetime.datetime.fromtimestamp(sess.start_time)
                    key = dt.strftime("%H:%M")
                    buckets[key] = buckets.get(key, 0) + sess.bytes_sent + sess.bytes_recv
                except Exception:
                    pass
            data = sorted(buckets.items())[-30:]
            self._traffic_chart.setData(data)

        def _update_protocols(self, case_data: dict) -> None:
            sessions = case_data.get("sessions", [])
            protos: Dict[str, int] = {}
            for sess in sessions:
                protos[sess.protocol] = protos.get(sess.protocol, 0) + 1
            data = sorted(protos.items(), key=lambda x: -x[1])
            self._proto_chart.setData(data)

        def _update_top_ips(self, case_data: dict) -> None:
            hosts = case_data.get("hosts", [])
            data = sorted(
                [(h.ip, h.bytes_sent + h.bytes_recv) for h in hosts],
                key=lambda x: -x[1],
            )[:10]
            self._top_ips_chart.setData(data)

else:
    class VisualizationWidget:
        def __init__(self, parent=None):
            pass

        def update_data(self, case_data: dict) -> None:
            pass
