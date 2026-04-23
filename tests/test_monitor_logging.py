from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import monitor


class MonitorLoggingTests(unittest.TestCase):
    def test_write_activity_event_appends_jsonl_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            activity_path = Path(tmpdir) / "activity.jsonl"
            with mock.patch.object(monitor, "ACTIVITY_LOG_FILE", activity_path):
                monitor.write_activity_event(
                    "analysis_completed",
                    ecosystem="pypi",
                    package="requests",
                    version="2.32.0",
                    verdict="benign",
                )

            lines = activity_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["event"], "analysis_completed")
            self.assertEqual(record["package"], "requests")
            self.assertEqual(record["verdict"], "benign")
            self.assertIn("ts", record)

    def test_analysis_excerpt_truncates_long_text(self) -> None:
        text = "A" * 5000
        excerpt = monitor._analysis_excerpt(text, limit=100)
        self.assertLess(len(excerpt), len(text))
        self.assertIn("truncated", excerpt)


if __name__ == "__main__":
    unittest.main()
