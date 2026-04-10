from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Callable

from .models import FileRecord

ResultCb = Callable[[FileRecord], None]


class VirusTotalQueue:
    def __init__(self, api_key: str, delay_s: float = 16.0) -> None:
        self.api_key = api_key.strip()
        self.delay_s = max(1.0, delay_s)
        self.queue: deque[FileRecord] = deque()
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def enqueue(self, rec: FileRecord) -> None:
        if not self.api_key:
            rec.vt_status = "disabled"
            return
        with self._lock:
            self.queue.append(rec)

    def start(self, on_result: ResultCb | None = None) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, args=(on_result,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self, on_result: ResultCb | None) -> None:
        while self._running:
            rec = None
            with self._lock:
                if self.queue:
                    rec = self.queue.popleft()
            if not rec:
                time.sleep(0.2)
                continue
            self._lookup(rec)
            if on_result:
                on_result(rec)
            time.sleep(self.delay_s)

    def _lookup(self, rec: FileRecord) -> None:
        url = f"https://www.virustotal.com/api/v3/files/{rec.sha256}"
        req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except urllib.error.HTTPError as exc:
            rec.vt_status = "error"
            rec.vt_result = f"http_{exc.code}"
            return
        except Exception:
            rec.vt_status = "error"
            rec.vt_result = "network_error"
            return
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        rec.vt_status = "done"
        rec.vt_result = f"malicious={malicious}, suspicious={suspicious}"
