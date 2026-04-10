"""Sessions table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel


class SessionsModel(BaseTableModel):
    HEADERS = [
        "ID", "Src IP", "Src Port", "Dst IP", "Dst Port",
        "Protocol", "Bytes", "Packets", "Start", "End", "State",
    ]

    def row_to_display(self, row):
        def fmt_ts(ts):
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(ts)

        total_bytes = row.bytes_sent + row.bytes_recv
        return [
            str(row.session_id),
            row.src_ip,
            str(row.src_port),
            row.dst_ip,
            str(row.dst_port),
            row.protocol,
            f"{total_bytes:,}",
            f"{row.packet_count:,}",
            fmt_ts(row.start_time),
            fmt_ts(row.end_time),
            row.tcp_state,
        ]
