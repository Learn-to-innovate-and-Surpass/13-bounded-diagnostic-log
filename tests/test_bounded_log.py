import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bounded_log import BoundedLog, CorruptLog, CriticalConflict, encode


class BoundedLogTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.log = BoundedLog(self.path, max_bytes=700, max_entries=3, max_event_bytes=256)

    def test_diagnostic_count_and_utf8_bytes_remain_bounded(self):
        for index in range(100):
            self.log.append_diagnostic({"message": "中文" * 20, "sequence": index})
            stats = self.log.diagnostic_stats()
            self.assertLessEqual(stats["entries"], 3)
            self.assertLessEqual(stats["utf8_bytes"], 700)
        rows = self.log.diagnostics()
        self.assertEqual(rows[-1]["payload"]["sequence"], 99)
        self.assertGreater(rows[0]["payload"]["sequence"], 0)
        self.assertEqual(sum(len(encode(row)) for row in rows),
                         self.log.diagnostic_stats()["utf8_bytes"])

    def test_byte_limit_applies_even_when_count_limit_is_large(self):
        log = BoundedLog(self.path, max_bytes=512, max_entries=100, max_event_bytes=256)
        for index in range(10):
            log.append_diagnostic({"sequence": index, "message": "x" * 120})
        self.assertLessEqual(log.diagnostic_stats()["utf8_bytes"], 512)
        self.assertLess(len(log.diagnostics()), 10)

    def test_oversize_event_has_size_hash_summary_without_original_payload(self):
        event = {"message": "大事件" * 10000}
        summary = self.log.append_diagnostic(event)
        self.assertEqual(summary["kind"], "oversize-summary")
        self.assertEqual(summary["original_utf8_bytes"], len(encode(event)))
        self.assertEqual(summary["sha256"], hashlib.sha256(encode(event)).hexdigest())
        self.assertNotIn("payload", summary)
        self.assertLessEqual(len(encode(summary)), 256)
        self.assertLessEqual(self.log.diagnostic_stats()["utf8_bytes"], 700)

    def test_critical_feedback_survives_roll_and_reopen_byte_for_byte(self):
        self.log.append_critical("task-1", {"status": "COMPLETE", "wire": "W1"})
        before = self.log.critical_path.read_bytes()
        for index in range(100):
            self.log.append_diagnostic({"sequence": index, "message": "x" * 3000})
        self.assertEqual(before, self.log.critical_path.read_bytes())
        reopened = BoundedLog(self.path, max_bytes=700, max_entries=3, max_event_bytes=256)
        self.assertEqual(reopened.critical_feedback()[0]["payload"]["wire"], "W1")

    def test_critical_idempotence_and_conflict(self):
        self.assertEqual(self.log.append_critical("task-1", {"status": "COMPLETE"}), "APPLIED")
        first = self.log.critical_path.read_bytes()
        self.assertEqual(self.log.append_critical("task-1", {"status": "COMPLETE"}), "DUPLICATE")
        self.assertEqual(first, self.log.critical_path.read_bytes())
        with self.assertRaises(CriticalConflict):
            self.log.append_critical("task-1", {"status": "FAILED"})
        self.assertEqual(len(self.log.critical_feedback()), 1)

    def test_critical_payload_is_not_summarized_by_diagnostic_limit(self):
        payload = {"message": "重要合成证据" * 1000}
        self.log.append_critical("large-critical", payload)
        self.assertEqual(self.log.critical_feedback()[0]["payload"], payload)
        self.assertGreater(self.log.critical_path.stat().st_size, 700)
        self.assertEqual(self.log.diagnostic_stats()["utf8_bytes"], 0)

    def test_invalid_json_values_fail_before_writing(self):
        for payload in ({"x": float("nan")}, {"x": float("inf")}, {"x": object()}):
            with self.assertRaises((TypeError, ValueError)):
                self.log.append_diagnostic(payload)
            with self.assertRaises((TypeError, ValueError)):
                self.log.append_critical("invalid", payload)
        self.assertFalse(self.log.diagnostic_path.exists())
        self.assertFalse(self.log.critical_path.exists())

    def test_malformed_or_partial_history_is_not_silently_truncated(self):
        for content in (b'{"event_id":"x"', b'not-json\n', b'{"x":NaN}\n'):
            with self.subTest(content=content):
                self.log.critical_path.write_bytes(content)
                with self.assertRaises(CorruptLog):
                    self.log.append_critical("new", {})
                self.assertEqual(self.log.critical_path.read_bytes(), content)

    def test_diagnostic_write_error_is_reported_and_critical_unchanged(self):
        self.log.append_critical("task-1", {"status": "COMPLETE"})
        critical_before = self.log.critical_path.read_bytes()
        self.log.append_diagnostic({"message": "old"})
        diagnostic_before = self.log.diagnostic_path.read_bytes()
        with patch("bounded_log.os.replace", side_effect=OSError("synthetic storage failure")):
            with self.assertRaises(OSError):
                self.log.append_diagnostic({"message": "new"})
        self.assertEqual(self.log.critical_path.read_bytes(), critical_before)
        self.assertEqual(self.log.diagnostic_path.read_bytes(), diagnostic_before)

    def test_critical_flush_error_is_reported(self):
        with patch("bounded_log.os.fsync", side_effect=OSError("synthetic flush failure")):
            with self.assertRaises(OSError):
                self.log.append_critical("task-1", {"status": "COMPLETE"})
        # The append may already exist despite the raised error. Retry by identity,
        # never assume a failed call means the bytes were absent.
        self.assertEqual(self.log.append_critical("task-1", {"status": "COMPLETE"}), "DUPLICATE")

    def test_critical_first_write_and_first_retry_both_report_failed_fsync(self):
        payload = {"status": "COMPLETE"}
        with patch("bounded_log.os.fsync", side_effect=OSError("synthetic flush failure")) as sync:
            with self.assertRaises(OSError):
                self.log.append_critical("task-1", payload)
            first_bytes = self.log.critical_path.read_bytes()
            with self.assertRaises(OSError):
                self.log.append_critical("task-1", payload)
            self.assertEqual(sync.call_count, 2)
            self.assertEqual(first_bytes, self.log.critical_path.read_bytes())
            self.assertEqual(len(self.log.critical_feedback()), 1)
        self.assertEqual(self.log.append_critical("task-1", payload), "DUPLICATE")
        self.assertEqual(first_bytes, self.log.critical_path.read_bytes())
        self.assertEqual(len(self.log.critical_feedback()), 1)

    def test_history_rejects_numeric_overflow_and_duplicate_nested_keys(self):
        records = {
            "diagnostics.jsonl": (
                b'{"event_id":"x","kind":"event","payload":{"score":1e999}}\n',
                b'{"event_id":"x","kind":"event","payload":{"status":"FAILED","status":"COMPLETE"}}\n',
            ),
            "critical-feedback.jsonl": (
                b'{"event_id":"x","payload":{"score":1e999}}\n',
                b'{"event_id":"x","payload":{"status":"FAILED","status":"COMPLETE"}}\n',
            ),
        }
        for filename, contents in records.items():
            for content in contents:
                with self.subTest(filename=filename, content=content):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / filename
                        path.write_bytes(content)
                        with self.assertRaises(CorruptLog):
                            BoundedLog(directory)
                        self.assertEqual(path.read_bytes(), content)

    def test_history_enforces_diagnostic_variant_and_critical_required_fields(self):
        bad_diagnostics = (
            {"event_id": "x", "kind": "event"},
            {"event_id": "x", "kind": "event", "payload": []},
            {"event_id": "x", "kind": "event", "payload": {}, "unexpected": 1},
            {"event_id": "x", "kind": "oversize-summary", "original_utf8_bytes": 1000},
            {"event_id": "x", "kind": "oversize-summary", "sha256": "0" * 64},
            {"event_id": "x", "kind": "oversize-summary",
             "original_utf8_bytes": True, "sha256": "0" * 64},
            {"event_id": "x", "kind": "oversize-summary",
             "original_utf8_bytes": 0, "sha256": "0" * 64},
            {"event_id": "x", "kind": "oversize-summary",
             "original_utf8_bytes": 1.5, "sha256": "0" * 64},
            {"event_id": "x", "kind": "oversize-summary",
             "original_utf8_bytes": 1000, "sha256": "not-a-digest"},
            {"event_id": "x", "kind": "oversize-summary",
             "original_utf8_bytes": 1000, "sha256": "0" * 64, "payload": {}},
        )
        bad_critical = ({"event_id": "x"}, {"event_id": "x", "payload": []},
                        {"event_id": " x ", "payload": {}})
        for filename, records in (("diagnostics.jsonl", bad_diagnostics),
                                  ("critical-feedback.jsonl", bad_critical)):
            for record in records:
                with self.subTest(filename=filename, record=record):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / filename
                        content = encode(record)
                        path.write_bytes(content)
                        with self.assertRaises(CorruptLog):
                            BoundedLog(directory)
                        self.assertEqual(path.read_bytes(), content)

    def test_reduced_budget_is_applied_when_reopened(self):
        larger = BoundedLog(self.path, max_bytes=4096, max_entries=10, max_event_bytes=1024)
        larger.append_diagnostic({"message": "x" * 500})
        smaller = BoundedLog(self.path, max_bytes=512, max_entries=1, max_event_bytes=256)
        self.assertLessEqual(smaller.diagnostic_stats()["utf8_bytes"], 512)
        self.assertLessEqual(smaller.diagnostic_stats()["entries"], 1)
        smaller.append_diagnostic({"message": "new"})
        self.assertLessEqual(smaller.diagnostic_stats()["utf8_bytes"], 512)
        self.assertEqual(smaller.diagnostic_stats()["entries"], 1)

    def test_bad_limits_and_event_shapes_are_rejected(self):
        for config in ({"max_entries": 0}, {"max_bytes": True},
                       {"max_event_bytes": 128}, {"max_event_bytes": 10000}):
            with self.assertRaises(ValueError):
                BoundedLog(self.path, **config)
        with self.assertRaises(ValueError):
            self.log.append_diagnostic([])
        with self.assertRaises(ValueError):
            self.log.append_critical("", {})
        with self.assertRaises(ValueError):
            self.log.append_critical("valid", [])


if __name__ == "__main__":
    unittest.main()
