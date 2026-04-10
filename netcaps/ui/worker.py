"""Background worker thread for PCAP analysis."""

import time
import traceback
from typing import TYPE_CHECKING

try:
    from PySide6.QtCore import QThread, Signal
    HAS_QT = True
except ImportError:
    HAS_QT = False
    # Provide stub so module is importable without PySide6
    class QThread:
        pass
    class Signal:
        def __init__(self, *args):
            pass

from netcaps.core.pcap_reader import read_pcap
from netcaps.core.session_engine import SessionEngine
from netcaps.core.host_tracker import HostTracker
from netcaps.core.timeline import TimelineEngine, EVENT_SESSION_START, EVENT_CREDENTIAL_FOUND, EVENT_FILE_EXTRACTED, EVENT_DNS_QUERY, EVENT_ALERT_TRIGGERED, EVENT_EMAIL_FOUND
from netcaps.extractors.dns_parser import DNSParser
from netcaps.extractors.http_extractor import HTTPExtractor
from netcaps.extractors.ftp_parser import FTPParser
from netcaps.extractors.smtp_parser import SMTPParser
from netcaps.extractors.file_carver import FileCarver
from netcaps.alerts.alert_engine import AlertEngine

if TYPE_CHECKING:
    from netcaps.core.case_store import CaseStore


if HAS_QT:
    class AnalysisWorker(QThread):
        progress = Signal(int)
        status = Signal(str)
        data_ready = Signal(dict)
        finished = Signal()
        error = Signal(str)

        def __init__(self, filepath: str, case_store: "CaseStore") -> None:
            super().__init__()
            self.filepath = filepath
            self.case_store = case_store
            self._stop_requested = False

        def stop(self) -> None:
            self._stop_requested = True

        def run(self) -> None:
            try:
                self._run_analysis()
            except Exception as e:
                self.error.emit(f"Analysis failed: {traceback.format_exc()}")
            finally:
                self.finished.emit()

        def _run_analysis(self) -> None:
            case_store = self.case_store
            session_engine = SessionEngine()
            host_tracker = HostTracker()
            dns_parser = DNSParser()
            http_extractor = HTTPExtractor()
            ftp_parser = FTPParser()
            smtp_parser = SMTPParser()
            file_carver = FileCarver()
            alert_engine = AlertEngine()
            timeline = TimelineEngine(case_store)

            packet_count = 0
            last_emit_time = time.time()
            last_status_time = time.time()
            _EMIT_INTERVAL = 0.2

            self.status.emit("Reading PCAP file...")

            try:
                packets = list(read_pcap(self.filepath))
            except Exception as e:
                self.error.emit(f"Failed to read PCAP: {e}")
                return

            total = len(packets)
            self.status.emit(f"Processing {total:,} packets...")

            processed_sessions = set()

            for i, (ts, raw) in enumerate(packets):
                if self._stop_requested:
                    break

                try:
                    host_tracker.process_packet(ts, raw)
                    for ip, host in host_tracker.hosts.items():
                        case_store.add_host(host)
                except Exception:
                    pass

                session_id = None
                try:
                    session_id = session_engine.process_packet(ts, raw)
                    if session_id is not None:
                        sess = session_engine.sessions[session_id]
                        case_store.update_session(sess)
                        if session_id not in processed_sessions:
                            processed_sessions.add(session_id)
                            timeline.add_event(
                                EVENT_SESSION_START,
                                f"Session started: {sess.src_ip}:{sess.src_port} -> {sess.dst_ip}:{sess.dst_port} ({sess.protocol})",
                                ts,
                                related_ip=sess.src_ip,
                                related_session=session_id,
                            )
                except Exception:
                    pass

                try:
                    dns_record = dns_parser.process_packet(ts, raw, session_id or 0)
                    if dns_record:
                        case_store.add_dns(dns_record)
                        timeline.add_event(
                            EVENT_DNS_QUERY,
                            f"DNS query: {dns_record.query} ({dns_record.qtype})",
                            ts,
                            related_ip=dns_record.src_ip,
                            related_session=session_id or 0,
                            severity="MEDIUM" if dns_record.is_anomalous else "LOW",
                        )
                        alert = alert_engine.check_dns_anomaly(dns_record)
                        if alert:
                            case_store.add_alert(alert)
                            timeline.add_event(
                                EVENT_ALERT_TRIGGERED,
                                alert.description,
                                ts,
                                related_ip=alert.src_ip,
                                related_session=alert.session_id,
                                severity=alert.severity,
                            )
                except Exception:
                    pass

                # HTTP / FTP / SMTP payload extraction
                if session_id is not None:
                    try:
                        sess = session_engine.sessions[session_id]
                        if sess.payload_data:
                            last_dir, last_chunk = sess.payload_data[-1]
                            src_ip, dst_ip = sess.src_ip, sess.dst_ip
                            sp, dp = sess.src_port, sess.dst_port

                            # FTP
                            ftp_cred = ftp_parser.process_payload(
                                ts, session_id, last_dir, last_chunk,
                                src_ip, dst_ip, sp, dp,
                            )
                            if ftp_cred:
                                case_store.add_credential(ftp_cred)
                                timeline.add_event(
                                    EVENT_CREDENTIAL_FOUND,
                                    f"FTP credential: {ftp_cred.username}@{ftp_cred.server_ip}",
                                    ts, related_ip=ftp_cred.client_ip,
                                    related_session=session_id, severity="HIGH",
                                )
                                a = alert_engine.check_credential_exposure(ftp_cred, ts)
                                if a:
                                    case_store.add_alert(a)

                            # SMTP
                            smtp_email = smtp_parser.process_payload(
                                ts, session_id, last_dir, last_chunk, sp, dp,
                            )
                            if smtp_email:
                                case_store.add_email(smtp_email)
                                timeline.add_event(
                                    EVENT_EMAIL_FOUND,
                                    f"Email: {smtp_email.sender} -> {smtp_email.receiver}",
                                    ts, related_ip=src_ip,
                                    related_session=session_id, severity="LOW",
                                )

                            # HTTP
                            http_files, http_creds = http_extractor.process_payload(
                                ts, session_id, last_dir, last_chunk,
                                src_ip, dst_ip, sp, dp,
                            )
                            for hf in http_files:
                                case_store.add_file(hf)
                                timeline.add_event(
                                    EVENT_FILE_EXTRACTED,
                                    f"HTTP file: {hf.filename} ({hf.content_type})",
                                    ts, related_ip=src_ip,
                                    related_session=session_id, severity="LOW",
                                )
                            for hc in http_creds:
                                case_store.add_credential(hc)
                                timeline.add_event(
                                    EVENT_CREDENTIAL_FOUND,
                                    f"HTTP credential: {hc.username}",
                                    ts, related_ip=src_ip,
                                    related_session=session_id, severity="HIGH",
                                )
                                a = alert_engine.check_credential_exposure(hc, ts)
                                if a:
                                    case_store.add_alert(a)
                    except Exception:
                        pass

                # Alert checks per packet
                try:
                    pkt_alerts = alert_engine.process_packet(ts, raw, session_id or 0)
                    for alert in pkt_alerts:
                        case_store.add_alert(alert)
                        timeline.add_event(
                            EVENT_ALERT_TRIGGERED,
                            alert.description,
                            ts,
                            related_ip=alert.src_ip,
                            related_session=alert.session_id,
                            severity=alert.severity,
                        )
                except Exception:
                    pass

                # Large transfer check every 100 packets
                if session_id is not None and packet_count % 100 == 0:
                    try:
                        sess = session_engine.sessions[session_id]
                        lt_alert = alert_engine.check_large_transfer(sess)
                        if lt_alert:
                            case_store.add_alert(lt_alert)
                    except Exception:
                        pass

                packet_count += 1
                now = time.time()

                if now - last_emit_time >= _EMIT_INTERVAL:
                    last_emit_time = now
                    self.data_ready.emit(case_store.get_all())
                    if total > 0:
                        self.progress.emit(int(100 * i / total))

                if now - last_status_time >= 1.0:
                    last_status_time = now
                    n_hosts = len(case_store.hosts)
                    n_sessions = len(case_store.sessions)
                    n_alerts = len(case_store.alerts)
                    self.status.emit(
                        f"Processed {packet_count:,}/{total:,} packets | "
                        f"Hosts: {n_hosts} | Sessions: {n_sessions} | Alerts: {n_alerts}"
                    )

            self.progress.emit(100)
            self.data_ready.emit(case_store.get_all())
            self.status.emit(
                f"Done. {packet_count:,} packets | "
                f"Hosts: {len(case_store.hosts)} | "
                f"Sessions: {len(case_store.sessions)} | "
                f"Alerts: {len(case_store.alerts)}"
            )

else:
    class AnalysisWorker:
        """Stub when PySide6 is not available."""
        def __init__(self, filepath: str, case_store: "CaseStore") -> None:
            self.filepath = filepath
            self.case_store = case_store
