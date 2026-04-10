"""VirusTotal integration for hash lookups."""

import threading
import time
from typing import Callable, Dict, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from PySide6.QtCore import QThread, Signal
    HAS_QT = True
except ImportError:
    HAS_QT = False

_VT_API_BASE = "https://www.virustotal.com/api/v3"
_RATE_LIMIT_INTERVAL = 15.5  # 4 requests/minute = 1 per 15s


class VirusTotalClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._last_request: float = 0.0
        self._lock = threading.Lock()

    def _wait_rate_limit(self) -> None:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            if elapsed < _RATE_LIMIT_INTERVAL:
                time.sleep(_RATE_LIMIT_INTERVAL - elapsed)
            self._last_request = time.time()

    def check_hash(self, hash_value: str) -> Dict:
        if not HAS_REQUESTS:
            return {"error": "requests library not available"}
        if not self.api_key:
            return {"error": "No API key configured"}

        self._wait_rate_limit()

        try:
            url = f"{_VT_API_BASE}/files/{hash_value}"
            headers = {"x-apikey": self.api_key}
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                return {
                    "hash": hash_value,
                    "malicious": malicious,
                    "total": total,
                    "verdict": "MALICIOUS" if malicious > 0 else "CLEAN",
                    "stats": stats,
                    "name": attrs.get("meaningful_name", ""),
                }
            elif resp.status_code == 404:
                return {"hash": hash_value, "verdict": "NOT_FOUND", "malicious": 0, "total": 0}
            elif resp.status_code == 401:
                return {"error": "Invalid API key"}
            elif resp.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}


if HAS_QT:
    class VTWorker(QThread):
        result_ready = Signal(str, dict)

        def __init__(self, client: VirusTotalClient, hash_value: str) -> None:
            super().__init__()
            self.client = client
            self.hash_value = hash_value

        def run(self) -> None:
            result = self.client.check_hash(self.hash_value)
            self.result_ready.emit(self.hash_value, result)

else:
    class VTWorker:
        def __init__(self, client, hash_value: str) -> None:
            self.client = client
            self.hash_value = hash_value
