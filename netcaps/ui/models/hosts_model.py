"""Hosts table model."""

import datetime
from netcaps.ui.models.base_model import BaseTableModel


class HostsModel(BaseTableModel):
    HEADERS = [
        "IP", "MAC", "Vendor", "Country",
        "Bytes Sent", "Bytes Recv", "Packets",
        "First Seen", "Last Seen",
    ]

    def row_to_display(self, row):
        def fmt_ts(ts):
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(ts)

        return [
            row.ip,
            row.mac,
            row.vendor,
            row.country,
            f"{row.bytes_sent:,}",
            f"{row.bytes_recv:,}",
            f"{row.packet_count:,}",
            fmt_ts(row.first_seen),
            fmt_ts(row.last_seen),
        ]
