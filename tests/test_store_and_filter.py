import unittest

from netcaps.filtering import FilterIndex
from netcaps.models import DNSRecord
from netcaps.store import CaseStore


class StoreFilterTests(unittest.TestCase):
    def test_case_store_dns_index_and_search(self) -> None:
        store = CaseStore()
        rec = DNSRecord(1.0, "1.2.3.4", "example.com", "1", "0")
        store.add_dns(rec)
        self.assertEqual(store.filter_rows("dns", "example"), [0])
        self.assertIn(0, store.index_domain_substring["example"])

    def test_filter_index(self) -> None:
        idx = FilterIndex()
        idx.append({"a": "Hello", "b": "World"})
        idx.append({"a": "Other"})
        self.assertEqual(idx.query("hello"), [0])
        self.assertEqual(idx.query(""), [0, 1])

    def test_store_max_events_guard(self) -> None:
        store = CaseStore(max_events=1)
        store.add_dns(DNSRecord(1.0, "1.1.1.1", "a.com", "1", "0"))
        store.add_dns(DNSRecord(2.0, "1.1.1.1", "b.com", "1", "0"))
        self.assertEqual(len(store.dns), 1)


if __name__ == "__main__":
    unittest.main()
