from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from .store import CaseStore

try:
    from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QThread, Signal
    from PySide6.QtWidgets import (
        QApplication,
        QHBoxLayout,
        QHeaderView,
        QLineEdit,
        QMainWindow,
        QMenu,
        QMessageBox,
        QSplitter,
        QTabWidget,
        QTableView,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except Exception:  # pragma: no cover
    QApplication = None
    QMainWindow = object
    QObject = object
    QThread = object
    Signal = None
    QAbstractTableModel = object
    QModelIndex = object
    Qt = None


def _to_row(item: Any) -> dict[str, Any]:
    if is_dataclass(item):
        return asdict(item)
    if isinstance(item, dict):
        return item
    return vars(item)


class DictTableModel(QAbstractTableModel):  # type: ignore[misc]
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        super().__init__()
        self.rows = rows or []
        self.headers = sorted({k for r in self.rows for k in r.keys()}) if self.rows else []

    def update_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.headers = sorted({k for r in self.rows for k in r.keys()}) if self.rows else []
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # type: ignore[override]
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # type: ignore[override]
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:  # type: ignore[override]
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        row = self.rows[index.row()]
        return str(row.get(self.headers[index.column()], ""))

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:  # type: ignore[override]
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and 0 <= section < len(self.headers):
            return self.headers[section]
        return str(section + 1)


class ParseWorker(QObject):  # type: ignore[misc]
    updated = Signal(object)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, parser_callable: Any) -> None:
        super().__init__()
        self.parser_callable = parser_callable

    def run(self) -> None:
        try:
            store = self.parser_callable(on_batch=lambda s: self.updated.emit(s))
            self.finished.emit(store)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):  # type: ignore[misc]
    TAB_NAMES = ["Hosts", "Sessions", "Credentials", "Files", "DNS", "Alerts", "Email", "Timeline"]

    def __init__(self) -> None:
        if QApplication is None:
            raise RuntimeError("PySide6 is required for UI.")
        super().__init__()
        self.setWindowTitle("NetCaps 0.2")
        self.resize(1400, 900)
        self.store = CaseStore()
        self.models: dict[str, DictTableModel] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        central = QWidget()
        outer = QVBoxLayout(central)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Global search...")
        self.search.textChanged.connect(self.apply_search)
        outer.addWidget(self.search)

        splitter = QSplitter()
        self.tabs = QTabWidget()
        for name in self.TAB_NAMES:
            table = QTableView()
            table.setSortingEnabled(True)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(lambda pos, t=table: self.show_menu(t, pos))
            model = DictTableModel([])
            table.setModel(model)
            self.models[name.lower()] = model
            self.tabs.addTab(table, name)
        splitter.addWidget(self.tabs)

        self.stream_view = QTextEdit()
        self.stream_view.setReadOnly(True)
        splitter.addWidget(self.stream_view)
        splitter.setSizes([1100, 300])
        outer.addWidget(splitter)
        self.setCentralWidget(central)

    def refresh(self, store: CaseStore) -> None:
        self.store = store
        data_map = {
            "hosts": [_to_row(v) for v in store.hosts.values()],
            "sessions": [_to_row(v) for v in store.sessions.values()],
            "credentials": [_to_row(v) for v in store.credentials],
            "files": [_to_row(v) for v in store.files],
            "dns": [_to_row(v) for v in store.dns],
            "alerts": [_to_row(v) for v in store.alerts],
            "email": [_to_row(v) for v in store.email],
            "timeline": [_to_row(v) for v in store.timeline],
        }
        for tab, rows in data_map.items():
            if tab in self.models:
                self.models[tab].update_rows(rows)

    def apply_search(self, text: str) -> None:
        q = text.strip().lower()
        if not q:
            self.refresh(self.store)
            return
        filtered = self.store.global_filter(q)
        data_map = {
            "dns": [self.store.dns[i] for i in filtered.get("dns", [])],
            "files": [self.store.files[i] for i in filtered.get("files", [])],
            "credentials": [self.store.credentials[i] for i in filtered.get("credentials", [])],
            "alerts": [self.store.alerts[i] for i in filtered.get("alerts", [])],
            "email": [self.store.email[i] for i in filtered.get("email", [])],
            "timeline": [self.store.timeline[i] for i in filtered.get("timeline", [])],
            "hosts": list(self.store.hosts.values()),
            "sessions": list(self.store.sessions.values()),
        }
        for tab, rows in data_map.items():
            if tab in self.models:
                self.models[tab].update_rows([_to_row(r) for r in rows])

    def show_menu(self, table: QTableView, pos: Any) -> None:
        menu = QMenu(table)
        copy_action = menu.addAction("Copy value")
        filter_action = menu.addAction("Filter by value")
        vt_action = menu.addAction("Check VirusTotal")
        related_action = menu.addAction("Open related sessions")
        action = menu.exec(table.viewport().mapToGlobal(pos))
        index = table.indexAt(pos)
        if not index.isValid():
            return
        value = index.data()
        if action == copy_action:
            QApplication.clipboard().setText(str(value))
        elif action == filter_action:
            self.search.setText(str(value))
        elif action == vt_action:
            QMessageBox.information(self, "VirusTotal", "VT check is queued via backend.")
        elif action == related_action:
            self.tabs.setCurrentIndex(1)
            self.search.setText(str(value))


def run_ui() -> int:
    if QApplication is None:
        raise RuntimeError("PySide6 is not installed")
    app = QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
