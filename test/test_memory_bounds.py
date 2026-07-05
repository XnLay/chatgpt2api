from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from services.log_service import LogService


class LogMemoryBoundsTests(unittest.TestCase):
    def test_list_reads_from_tail_without_reading_whole_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "logs.jsonl"
            with path.open("w", encoding="utf-8") as file:
                for index in range(1000):
                    file.write(json.dumps({
                        "id": f"log-{index}",
                        "time": f"2026-07-05 12:{index % 60:02d}:00",
                        "type": "call",
                        "summary": f"summary-{index}",
                        "detail": {"index": index},
                    }, ensure_ascii=False) + "\n")

            service = LogService(path)
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("read_text should not be used")):
                items = service.list(limit=5)

        self.assertEqual([item["id"] for item in items], ["log-999", "log-998", "log-997", "log-996", "log-995"])

    def test_add_trims_log_file_to_bounded_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "logs.jsonl"
            service = LogService(path)
            with (
                mock.patch("services.log_service.LOG_FILE_MAX_BYTES", 512),
                mock.patch("services.log_service.LOG_FILE_KEEP_BYTES", 256),
            ):
                for index in range(30):
                    service.add("call", f"summary-{index}", {"payload": "x" * 80})

            self.assertLessEqual(path.stat().st_size, 512)
            items = service.list(limit=3)

        self.assertEqual(items[0]["summary"], "summary-29")

    def test_delete_rewrites_file_streamingly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "logs.jsonl"
            service = LogService(path)
            for index in range(5):
                service.add("call", f"summary-{index}", {"index": index})
            target_id = service.list(limit=5)[2]["id"]

            with mock.patch.object(Path, "read_text", side_effect=AssertionError("read_text should not be used")):
                result = service.delete([target_id])

            items = service.list(limit=10)

        self.assertEqual(result, {"removed": 1})
        self.assertNotIn(target_id, {item["id"] for item in items})


if __name__ == "__main__":
    unittest.main()
