import json
import tempfile
import unittest
from pathlib import Path

from netcaps.exporting import export_csv, export_html_report, export_json, generate_attack_summary
from netcaps.models import AlertRecord
from netcaps.store import CaseStore


class ExportTests(unittest.TestCase):
    def test_exports(self) -> None:
        store = CaseStore()
        store.add_alert(AlertRecord(1.0, "X", "high", "test"))
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            export_csv(store.alerts, base / "alerts.csv")
            export_json(store, base / "case.json")
            export_html_report(store, base / "report.html")
            self.assertTrue((base / "alerts.csv").exists())
            self.assertTrue((base / "case.json").exists())
            self.assertTrue((base / "report.html").exists())
            obj = json.loads((base / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(len(obj["alerts"]), 1)
            self.assertIn("Detected", generate_attack_summary(store))


if __name__ == "__main__":
    unittest.main()
