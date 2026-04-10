from __future__ import annotations

import csv
from pathlib import Path


class Enrichment:
    def __init__(self, mac_vendor_file: str | None = None, geoip_file: str | None = None) -> None:
        self.mac_vendor: dict[str, str] = {}
        self.geoip_prefix: list[tuple[str, str]] = []
        if mac_vendor_file:
            self._load_mac(mac_vendor_file)
        if geoip_file:
            self._load_geo(geoip_file)

    def _load_mac(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "," not in line:
                    continue
                prefix, vendor = line.strip().split(",", 1)
                self.mac_vendor[prefix.upper().replace(":", "")] = vendor

    def _load_geo(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    self.geoip_prefix.append((row[0], row[1]))

    def lookup_vendor(self, mac: str | None) -> str | None:
        if not mac:
            return None
        key = mac.upper().replace(":", "").replace("-", "")[:6]
        return self.mac_vendor.get(key)

    def lookup_country(self, ip: str) -> str | None:
        for prefix, country in self.geoip_prefix:
            if ip.startswith(prefix):
                return country
        return None
