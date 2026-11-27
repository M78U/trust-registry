from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from trust_maintainer import enqueue, plan, record, parser, execute
from sheca_source_review_index import listing, INDEX
from sheca_source_review_disposition import inspect
from sheca_source_review_queue import verify
from test_sheca_source_review_queue import batch
from test_sheca_source_diff import page


class MaintainerTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.batch = batch(page(), page(root=[("New", "d"*40)]))
        self.pin = plan(self.batch)["batchSHA256"]
        self.task = self.batch["tasks"][0]["taskId"]

    def test_plan_pin_and_enqueue(self):
        self.assertEqual(plan(self.batch), plan(self.batch))
        self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaises(ValueError):
            enqueue(self.root, self.batch, "0"*64, "2026-11-28T01:00:00Z")
        self.assertEqual(list(self.root.iterdir()), [])
        result, code = enqueue(self.root, self.batch, self.pin, "2026-11-28T01:00:00Z")
        self.assertEqual(code, 0)
        self.assertEqual(result["committed"]["status"], "BATCH_CREATED")
        self.assertEqual(listing(self.root)["matching"], self.batch["taskCount"])
        result, code = enqueue(self.root, self.batch, self.pin, "2026-11-28T01:00:00Z")
        self.assertEqual(code, 0)
        self.assertEqual(result["committed"]["status"], "EXACT_BATCH_REUSED")

    def test_record_updates_open_count(self):
        enqueue(self.root, self.batch, self.pin, "2026-11-28T01:00:00Z")
        result, code = record(self.root, self.batch, self.pin, self.task, "EMPTY",
                              "REVIEW_COMPLETE", "2026-11-28T02:00:00Z", "maintainer", "Reviewed")
        self.assertEqual(code, 0)
        self.assertEqual(result["committed"]["status"], "REVIEW_COMPLETE")
        self.assertEqual(listing(self.root)["matching"], self.batch["taskCount"]-1)
        self.assertFalse(result["liveProfileAccepted"])

    def test_partial_commit_and_safe_recovery(self):
        (self.root / INDEX).write_bytes(b"corrupt")
        result, code = enqueue(self.root, self.batch, self.pin, "2026-11-28T01:00:00Z")
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "WRITE_COMMITTED_INDEX_REFRESH_FAILED")
        self.assertEqual(verify(self.root, self.batch, self.pin)["status"], "PINNED_BATCH_REPLAYED")
        result, code = record(self.root, self.batch, self.pin, self.task, "EMPTY",
                              "REVIEW_COMPLETE", "2026-11-28T02:00:00Z", "maintainer", "Reviewed")
        self.assertEqual(code, 1)
        self.assertEqual(result["committed"]["eventCount"], 1)
        self.assertEqual(inspect(self.root, self.batch, self.pin, self.task)["status"], "REVIEW_COMPLETE")
        with self.assertRaises(ValueError):
            record(self.root, self.batch, self.pin, self.task, "EMPTY",
                   "REVIEW_COMPLETE", "2026-11-28T03:00:00Z", "maintainer", "Reviewed again")
        self.assertEqual((self.root / INDEX).read_bytes(), b"corrupt")

    def test_check_delegation(self):
        binary = self.root / "trust-registry"
        binary.touch()
        args = parser().parse_args(["check", "--binary", str(binary), "--store", str(self.root),
                                    "--interval", "168h", "--max-fetches", "1", "--id", "sheca-repository"])
        with patch("trust_maintainer.subprocess.run", return_value=subprocess.CompletedProcess([], 1)) as run:
            self.assertEqual(execute(args), (None, 1))
            run.assert_called_once_with([str(binary), "sources", "monitor-run", "--store", str(self.root),
                                         "--interval", "168h", "--max-fetches", "1", "--id", "sheca-repository"],
                                        check=False, timeout=360)


if __name__ == "__main__":
    unittest.main()
