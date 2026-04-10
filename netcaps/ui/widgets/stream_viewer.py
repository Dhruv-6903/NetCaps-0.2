"""Stream viewer dialog for inspecting TCP/UDP session payloads."""

try:
    from PySide6.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QTextEdit,
        QLabel, QPushButton, QWidget,
    )
    from PySide6.QtGui import QFont, QTextCharFormat, QColor, QTextCursor
    from PySide6.QtCore import Qt
    HAS_QT = True
except ImportError:
    HAS_QT = False


def _bytes_to_hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def _payload_to_ascii(payload_data: list) -> list:
    """Return list of (direction, text) tuples."""
    result = []
    for direction, chunk in payload_data:
        text = chunk.decode("latin-1", errors="replace")
        result.append((direction, text))
    return result


if HAS_QT:
    class StreamViewer(QDialog):
        def __init__(self, session, parent=None):
            super().__init__(parent)
            self.session = session
            self.setWindowTitle(
                f"Stream Viewer - Session {session.session_id}: "
                f"{session.src_ip}:{session.src_port} <-> "
                f"{session.dst_ip}:{session.dst_port}"
            )
            self.resize(900, 600)
            self._build_ui()

        def _build_ui(self):
            layout = QVBoxLayout(self)

            # Info bar
            total_bytes = self.session.bytes_sent + self.session.bytes_recv
            payload_bytes = sum(len(c) for _, c in self.session.payload_data)
            info = (
                f"Protocol: {self.session.protocol}  |  "
                f"Total bytes: {total_bytes:,}  |  "
                f"Payload captured: {payload_bytes:,} bytes  |  "
                f"State: {self.session.tcp_state}"
            )
            info_label = QLabel(info)
            layout.addWidget(info_label)

            if payload_bytes >= 1024 * 1024:
                warn = QLabel("⚠ Payload truncated at 1MB limit")
                warn.setStyleSheet("color: orange; font-weight: bold;")
                layout.addWidget(warn)

            tabs = QTabWidget()
            layout.addWidget(tabs)

            # ASCII tab
            ascii_widget = QWidget()
            ascii_layout = QVBoxLayout(ascii_widget)
            self._ascii_edit = QTextEdit()
            self._ascii_edit.setReadOnly(True)
            self._ascii_edit.setFont(QFont("Courier", 10))
            ascii_layout.addWidget(self._ascii_edit)
            tabs.addTab(ascii_widget, "ASCII")

            # Hex tab
            hex_widget = QWidget()
            hex_layout = QVBoxLayout(hex_widget)
            self._hex_edit = QTextEdit()
            self._hex_edit.setReadOnly(True)
            self._hex_edit.setFont(QFont("Courier", 10))
            hex_layout.addWidget(self._hex_edit)
            tabs.addTab(hex_widget, "Hex Dump")

            # Close button
            btn_layout = QHBoxLayout()
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)
            btn_layout.addStretch()
            btn_layout.addWidget(close_btn)
            layout.addLayout(btn_layout)

            self._populate_ascii()
            self._populate_hex()

        def _populate_ascii(self):
            edit = self._ascii_edit
            cursor = edit.textCursor()
            edit.clear()

            sent_fmt = QTextCharFormat()
            sent_fmt.setBackground(QColor("#ddeeff"))

            recv_fmt = QTextCharFormat()
            recv_fmt.setBackground(QColor("#ffdddd"))

            default_fmt = QTextCharFormat()

            for direction, chunk in self.session.payload_data:
                text = chunk.decode("latin-1", errors="replace")
                fmt = sent_fmt if direction == "sent" else recv_fmt
                cursor.movePosition(QTextCursor.End)
                cursor.insertText(text, fmt)

            edit.setTextCursor(cursor)

        def _populate_hex(self):
            edit = self._hex_edit
            cursor = edit.textCursor()
            edit.clear()

            sent_fmt = QTextCharFormat()
            sent_fmt.setBackground(QColor("#ddeeff"))

            recv_fmt = QTextCharFormat()
            recv_fmt.setBackground(QColor("#ffdddd"))

            for direction, chunk in self.session.payload_data:
                fmt = sent_fmt if direction == "sent" else recv_fmt
                header = f"\n--- {'SENT' if direction == 'sent' else 'RECV'} ({len(chunk)} bytes) ---\n"
                cursor.movePosition(QTextCursor.End)
                cursor.insertText(header, fmt)
                cursor.insertText(_bytes_to_hex_dump(chunk) + "\n", fmt)

            edit.setTextCursor(cursor)

else:
    class StreamViewer:
        def __init__(self, session, parent=None):
            self.session = session
