"""Main application window for NetCaps."""

import os

try:
    from PySide6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTableView, QLineEdit, QLabel,
        QProgressBar, QStatusBar, QMenuBar, QMenu,
        QToolBar, QFileDialog, QMessageBox, QInputDialog,
        QHeaderView, QAbstractItemView, QSplitter, QDialog,
        QDialogButtonBox, QFormLayout,
    )
    from PySide6.QtCore import Qt, QTimer, QSize, QSortFilterProxyModel
    from PySide6.QtGui import QAction, QIcon, QKeySequence
    HAS_QT = True
except ImportError:
    HAS_QT = False

from netcaps.core.case_store import CaseStore
from netcaps.export.exporter import Exporter

if HAS_QT:
    from netcaps.ui.worker import AnalysisWorker
    from netcaps.ui.models.hosts_model import HostsModel
    from netcaps.ui.models.sessions_model import SessionsModel
    from netcaps.ui.models.dns_model import DNSModel
    from netcaps.ui.models.files_model import FilesModel
    from netcaps.ui.models.credentials_model import CredentialsModel
    from netcaps.ui.models.alerts_model import AlertsModel
    from netcaps.ui.models.email_model import EmailModel
    from netcaps.ui.models.timeline_model import TimelineModel
    from netcaps.ui.widgets.stream_viewer import StreamViewer
    from netcaps.ui.widgets.visualizations import VisualizationWidget
    from netcaps.integrations.virustotal import VirusTotalClient, VTWorker


if HAS_QT:
    def _make_table_view(model) -> QTableView:
        view = QTableView()
        view.setModel(model)
        view.setSelectionBehavior(QAbstractItemView.SelectRows)
        view.setAlternatingRowColors(True)
        view.setSortingEnabled(True)
        view.horizontalHeader().setStretchLastSection(True)
        view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        view.setContextMenuPolicy(Qt.CustomContextMenu)
        return view

    def _make_tab_widget(model, has_stream=False, has_vt=False):
        """Return (widget, filter_bar, table_view)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        filter_bar = QLineEdit()
        filter_bar.setPlaceholderText("Filter this tab...")
        layout.addWidget(filter_bar)

        view = _make_table_view(model)
        layout.addWidget(view)

        filter_bar.textChanged.connect(model.filterByText)

        return widget, filter_bar, view

    class VTSettingsDialog(QDialog):
        def __init__(self, current_key: str = "", parent=None):
            super().__init__(parent)
            self.setWindowTitle("VirusTotal API Settings")
            layout = QFormLayout(self)
            self._key_edit = QLineEdit(current_key)
            self._key_edit.setMinimumWidth(350)
            self._key_edit.setEchoMode(QLineEdit.Password)
            layout.addRow("API Key:", self._key_edit)
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addRow(buttons)

        def get_key(self) -> str:
            return self._key_edit.text().strip()

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("NetCaps 0.2 - Network Forensics")
            self.resize(1400, 800)

            self._case_store = CaseStore()
            self._exporter = Exporter()
            self._worker = None
            self._vt_api_key = ""
            self._vt_client = None
            self._vt_workers = []

            self._build_ui()
            self._build_menus()
            self._build_toolbar()
            self._setup_update_timer()

        def _build_ui(self) -> None:
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setContentsMargins(6, 6, 6, 6)
            main_layout.setSpacing(4)

            # Global search
            search_row = QHBoxLayout()
            search_row.addWidget(QLabel("Global Search:"))
            self._global_search = QLineEdit()
            self._global_search.setPlaceholderText("Search all tabs...")
            self._global_search.textChanged.connect(self._on_global_search)
            search_row.addWidget(self._global_search)
            main_layout.addLayout(search_row)

            # Progress bar
            self._progress = QProgressBar()
            self._progress.setVisible(False)
            self._progress.setMaximum(100)
            main_layout.addWidget(self._progress)

            # Tab widget
            self._tabs = QTabWidget()
            main_layout.addWidget(self._tabs)

            # Models
            self._hosts_model = HostsModel()
            self._sessions_model = SessionsModel()
            self._dns_model = DNSModel()
            self._files_model = FilesModel()
            self._creds_model = CredentialsModel()
            self._alerts_model = AlertsModel()
            self._email_model = EmailModel()
            self._timeline_model = TimelineModel()

            # Build tabs
            hosts_tab, self._hosts_filter, self._hosts_view = _make_tab_widget(self._hosts_model)
            sessions_tab, self._sessions_filter, self._sessions_view = _make_tab_widget(self._sessions_model, has_stream=True)
            creds_tab, self._creds_filter, self._creds_view = _make_tab_widget(self._creds_model)
            files_tab, self._files_filter, self._files_view = _make_tab_widget(self._files_model, has_vt=True)
            dns_tab, self._dns_filter, self._dns_view = _make_tab_widget(self._dns_model)
            alerts_tab, self._alerts_filter, self._alerts_view = _make_tab_widget(self._alerts_model)
            email_tab, self._email_filter, self._email_view = _make_tab_widget(self._email_model)
            timeline_tab, self._timeline_filter, self._timeline_view = _make_tab_widget(self._timeline_model)

            self._tabs.addTab(hosts_tab, "🖥 Hosts")
            self._tabs.addTab(sessions_tab, "🔗 Sessions")
            self._tabs.addTab(creds_tab, "🔑 Credentials")
            self._tabs.addTab(files_tab, "📁 Files")
            self._tabs.addTab(dns_tab, "🌐 DNS")
            self._tabs.addTab(alerts_tab, "⚠ Alerts")
            self._tabs.addTab(email_tab, "✉ Email")
            self._tabs.addTab(timeline_tab, "📅 Timeline")

            # Context menus
            self._sessions_view.customContextMenuRequested.connect(
                lambda pos: self._show_context_menu(pos, self._sessions_view, self._sessions_model, has_stream=True)
            )
            self._files_view.customContextMenuRequested.connect(
                lambda pos: self._show_context_menu(pos, self._files_view, self._files_model, has_vt=True)
            )
            for view, model in [
                (self._hosts_view, self._hosts_model),
                (self._creds_view, self._creds_model),
                (self._dns_view, self._dns_model),
                (self._alerts_view, self._alerts_model),
                (self._email_view, self._email_model),
                (self._timeline_view, self._timeline_model),
            ]:
                view.customContextMenuRequested.connect(
                    lambda pos, v=view, m=model: self._show_context_menu(pos, v, m)
                )

            # Status bar
            self._status_bar = QStatusBar()
            self.setStatusBar(self._status_bar)
            self._status_label = QLabel("Ready. Open a PCAP file to begin.")
            self._status_bar.addWidget(self._status_label)

        def _build_menus(self) -> None:
            menubar = self.menuBar()

            # File menu
            file_menu = menubar.addMenu("&File")

            open_action = QAction("&Open PCAP...", self)
            open_action.setShortcut(QKeySequence.Open)
            open_action.triggered.connect(self._open_pcap)
            file_menu.addAction(open_action)

            file_menu.addSeparator()

            export_csv_action = QAction("Export &CSV...", self)
            export_csv_action.triggered.connect(self._export_csv)
            file_menu.addAction(export_csv_action)

            export_json_action = QAction("Export &JSON...", self)
            export_json_action.triggered.connect(self._export_json)
            file_menu.addAction(export_json_action)

            export_html_action = QAction("Export &HTML Report...", self)
            export_html_action.triggered.connect(self._export_html)
            file_menu.addAction(export_html_action)

            file_menu.addSeparator()

            exit_action = QAction("E&xit", self)
            exit_action.setShortcut(QKeySequence.Quit)
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

            # Tools menu
            tools_menu = menubar.addMenu("&Tools")
            vt_action = QAction("VirusTotal &Settings...", self)
            vt_action.triggered.connect(self._show_vt_settings)
            tools_menu.addAction(vt_action)

            # Help menu
            help_menu = menubar.addMenu("&Help")
            about_action = QAction("&About NetCaps", self)
            about_action.triggered.connect(self._show_about)
            help_menu.addAction(about_action)

        def _build_toolbar(self) -> None:
            toolbar = self.addToolBar("Main")
            toolbar.setMovable(False)

            open_btn = QAction("📂 Open PCAP", self)
            open_btn.triggered.connect(self._open_pcap)
            toolbar.addAction(open_btn)

            export_btn = QAction("💾 Export HTML", self)
            export_btn.triggered.connect(self._export_html)
            toolbar.addAction(export_btn)

        def _setup_update_timer(self) -> None:
            self._update_timer = QTimer(self)
            self._update_timer.setInterval(200)
            self._update_timer.timeout.connect(self._flush_pending_data)
            self._pending_data = None

        def _open_pcap(self) -> None:
            filepath, _ = QFileDialog.getOpenFileName(
                self, "Open PCAP File", "",
                "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
            )
            if not filepath:
                return

            # Reset state
            self._case_store.clear()
            self._pending_data = None

            if self._worker and self._worker.isRunning():
                self._worker.stop()
                self._worker.wait(2000)

            self._progress.setVisible(True)
            self._progress.setValue(0)
            self._status_label.setText(f"Loading: {os.path.basename(filepath)}")

            self._worker = AnalysisWorker(filepath, self._case_store)
            self._worker.progress.connect(self._progress.setValue)
            self._worker.status.connect(self._status_label.setText)
            self._worker.data_ready.connect(self._on_data_ready)
            self._worker.finished.connect(self._on_analysis_finished)
            self._worker.error.connect(self._on_analysis_error)
            self._worker.start()
            self._update_timer.start()

        def _on_data_ready(self, data: dict) -> None:
            self._pending_data = data

        def _flush_pending_data(self) -> None:
            if self._pending_data is None:
                return
            data = self._pending_data
            self._pending_data = None
            self._update_models(data)

        def _update_models(self, data: dict) -> None:
            self._hosts_model.setData(data.get("hosts", []))
            self._sessions_model.setData(data.get("sessions", []))
            self._dns_model.setData(data.get("dns_records", []))
            self._files_model.setData(data.get("files", []))
            self._creds_model.setData(data.get("credentials", []))
            self._alerts_model.setData(data.get("alerts", []))
            self._email_model.setData(data.get("emails", []))
            self._timeline_model.setData(data.get("timeline", []))

            # Update tab titles with counts
            self._tabs.setTabText(0, f"🖥 Hosts ({len(data.get('hosts', []))})")
            self._tabs.setTabText(1, f"🔗 Sessions ({len(data.get('sessions', []))})")
            self._tabs.setTabText(2, f"🔑 Credentials ({len(data.get('credentials', []))})")
            self._tabs.setTabText(3, f"📁 Files ({len(data.get('files', []))})")
            self._tabs.setTabText(4, f"🌐 DNS ({len(data.get('dns_records', []))})")
            self._tabs.setTabText(5, f"⚠ Alerts ({len(data.get('alerts', []))})")
            self._tabs.setTabText(6, f"✉ Email ({len(data.get('emails', []))})")
            self._tabs.setTabText(7, f"📅 Timeline ({len(data.get('timeline', []))})")

        def _on_analysis_finished(self) -> None:
            self._update_timer.stop()
            if self._pending_data:
                self._flush_pending_data()
            self._progress.setVisible(False)

        def _on_analysis_error(self, msg: str) -> None:
            self._update_timer.stop()
            self._progress.setVisible(False)
            QMessageBox.critical(self, "Analysis Error", msg)

        def _on_global_search(self, text: str) -> None:
            for model in [
                self._hosts_model, self._sessions_model, self._dns_model,
                self._files_model, self._creds_model, self._alerts_model,
                self._email_model, self._timeline_model,
            ]:
                model.filterByText(text)

        def _show_context_menu(self, pos, view, model, has_stream=False, has_vt=False) -> None:
            from PySide6.QtWidgets import QMenu
            index = view.indexAt(pos)
            menu = QMenu(self)

            copy_action = menu.addAction("📋 Copy Cell")
            filter_action = menu.addAction("🔍 Filter by This Value")

            stream_action = None
            if has_stream:
                stream_action = menu.addAction("🔎 Open Stream Viewer")

            vt_action = None
            if has_vt:
                vt_action = menu.addAction("🦠 Check VirusTotal")

            action = menu.exec(view.viewport().mapToGlobal(pos))

            if action == copy_action and index.isValid():
                val = model.getCellValue(index)
                from PySide6.QtWidgets import QApplication
                QApplication.clipboard().setText(val)

            elif action == filter_action and index.isValid():
                val = model.getCellValue(index)
                model.filterByText(val)

            elif stream_action and action == stream_action and index.isValid():
                row = model.getRow(index)
                if row is not None:
                    sid = int(getattr(row, "session_id", 0))
                    sess = self._case_store.sessions.get(sid)
                    if sess:
                        dlg = StreamViewer(sess, self)
                        dlg.exec()
                    else:
                        QMessageBox.information(self, "Stream Viewer", "Session data not available.")

            elif vt_action and action == vt_action and index.isValid():
                row = model.getRow(index)
                if row is not None:
                    sha256 = getattr(row, "sha256", "")
                    if not sha256:
                        QMessageBox.information(self, "VirusTotal", "No hash available for this file.")
                        return
                    if not self._vt_api_key:
                        QMessageBox.warning(
                            self, "VirusTotal",
                            "No API key configured. Go to Tools > VirusTotal Settings."
                        )
                        return
                    if not self._vt_client:
                        self._vt_client = VirusTotalClient(self._vt_api_key)
                    self._status_label.setText(f"Checking VirusTotal for {sha256[:16]}...")
                    worker = VTWorker(self._vt_client, sha256)
                    worker.result_ready.connect(self._on_vt_result)
                    self._vt_workers.append(worker)
                    worker.start()

        def _on_vt_result(self, hash_value: str, result: dict) -> None:
            if "error" in result:
                QMessageBox.warning(self, "VirusTotal Error", result["error"])
            else:
                verdict = result.get("verdict", "UNKNOWN")
                malicious = result.get("malicious", 0)
                total = result.get("total", 0)
                name = result.get("name", "")
                msg = (
                    f"Hash: {hash_value}\n"
                    f"Verdict: {verdict}\n"
                    f"Detections: {malicious}/{total}\n"
                )
                if name:
                    msg += f"Name: {name}\n"
                QMessageBox.information(self, "VirusTotal Result", msg)
            self._status_label.setText("VirusTotal check complete.")

        def _show_vt_settings(self) -> None:
            dlg = VTSettingsDialog(self._vt_api_key, self)
            if dlg.exec() == QDialog.Accepted:
                self._vt_api_key = dlg.get_key()
                self._vt_client = VirusTotalClient(self._vt_api_key) if self._vt_api_key else None

        def _show_about(self) -> None:
            QMessageBox.about(
                self, "About NetCaps",
                "<h2>NetCaps 0.2</h2>"
                "<p>Desktop Network Forensics Application</p>"
                "<p>Analyze PCAP files to extract hosts, sessions, credentials, "
                "files, DNS queries, emails, and security alerts.</p>"
                "<p><b>Supported formats:</b> PCAP, PCAPNG</p>"
            )

        def _get_current_tab_data(self):
            """Return (list_of_rows, tab_name) for the currently selected tab."""
            idx = self._tabs.currentIndex()
            tab_map = [
                (self._hosts_model, "hosts"),
                (self._sessions_model, "sessions"),
                (self._creds_model, "credentials"),
                (self._files_model, "files"),
                (self._dns_model, "dns"),
                (self._alerts_model, "alerts"),
                (self._email_model, "email"),
                (self._timeline_model, "timeline"),
            ]
            if 0 <= idx < len(tab_map):
                model, name = tab_map[idx]
                return model._filtered_rows, name
            return [], "unknown"

        def _export_csv(self) -> None:
            rows, tab_name = self._get_current_tab_data()
            if not rows:
                QMessageBox.information(self, "Export", "No data to export.")
                return
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Export CSV", f"{tab_name}.csv", "CSV Files (*.csv)"
            )
            if filepath:
                try:
                    self._exporter.export_csv(rows, filepath, tab_name)
                    QMessageBox.information(self, "Export", f"Exported to {filepath}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", str(e))

        def _export_json(self) -> None:
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Export JSON", "case_export.json", "JSON Files (*.json)"
            )
            if filepath:
                try:
                    self._exporter.export_json(self._case_store, filepath)
                    QMessageBox.information(self, "Export", f"Exported to {filepath}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", str(e))

        def _export_html(self) -> None:
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Export HTML Report", "forensic_report.html", "HTML Files (*.html)"
            )
            if filepath:
                try:
                    self._exporter.export_html(self._case_store, filepath)
                    QMessageBox.information(self, "Export", f"Report saved to {filepath}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", str(e))

        def closeEvent(self, event) -> None:
            if self._worker and self._worker.isRunning():
                self._worker.stop()
                self._worker.wait(3000)
            for w in self._vt_workers:
                if hasattr(w, "isRunning") and w.isRunning():
                    w.wait(1000)
            event.accept()

else:
    class MainWindow:
        """Stub when PySide6 is not available."""
        def __init__(self) -> None:
            pass
