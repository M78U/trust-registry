import tempfile
from pathlib import Path
import unittest

from sheca_source_review_index import INDEX, listing, refresh
from sheca_source_review_disposition import append
from sheca_source_review_queue import persist
from test_sheca_source_review_queue import batch
from test_sheca_source_diff import page


class ReviewIndexTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.batch = batch(page(), page(root=[("New", "d"*40)]))
        self.pin = persist(self.root, self.batch)["batchSHA256"]
        self.args = (self.root, self.batch, self.pin)
        self.task = self.batch["tasks"][0]["taskId"]

    def test_explicit_refresh_filter_and_pagination(self):
        self.assertEqual(listing(self.root)["batchCount"], 0)
        self.assertFalse((self.root / INDEX).exists())
        refresh(*self.args, "2026-11-28T01:00:00Z")
        a = listing(self.root, limit=1)
        self.assertEqual(a["matching"], self.batch["taskCount"])
        self.assertEqual(a["nextOffset"], 1)
        self.assertEqual(a["freshness"], "NOT_RECHECKED")
        event = append(*self.args, self.task, "EMPTY", "REVIEW_COMPLETE",
                       "2026-11-28T02:00:00Z", "maintainer", "Reviewed")
        self.assertEqual(listing(self.root)["matching"], self.batch["taskCount"])
        refresh(*self.args, "2026-11-28T03:00:00Z")
        self.assertEqual(listing(self.root)["matching"], self.batch["taskCount"]-1)
        closed = listing(self.root, "REVIEW_COMPLETE")
        self.assertEqual(closed["tasks"][0]["headSHA256"], event["headSHA256"])
        self.assertEqual(closed["trustStatus"], "NOT_ESTABLISHED")

    def test_multiple_batches_idempotence(self):
        first = refresh(*self.args, "2026-11-28T01:00:00Z")
        self.assertEqual(first, refresh(*self.args, "2026-11-28T01:00:00Z"))
        other = batch(page(), page(root=[("Other", "e"*40)]))
        pin = persist(self.root, other)["batchSHA256"]
        refresh(self.root, other, pin, "2026-11-28T01:00:00Z")
        self.assertEqual(listing(self.root)["batchCount"], 2)
        self.assertEqual(listing(self.root)["matching"], self.batch["taskCount"] + other["taskCount"])

    def test_conflict_and_history_loss(self):
        append(*self.args, self.task, "EMPTY", "NEEDS_INVESTIGATION",
               "2026-11-28T01:00:00Z", "maintainer", "Investigate")
        refresh(*self.args, "2026-11-28T02:00:00Z")
        original = (self.root / INDEX).read_bytes()
        with self.assertRaises(ValueError):
            refresh(*self.args, "2026-11-28T01:00:00Z")
        path = self.root / (self.batch["batchId"]+".dispositions") / self.task / "0001.json"
        path.unlink()
        with self.assertRaises(ValueError):
            refresh(*self.args, "2026-11-28T03:00:00Z")
        self.assertEqual((self.root / INDEX).read_bytes(), original)

    def test_bad_index_lock_and_pin(self):
        with self.assertRaises(ValueError):
            refresh(self.root, self.batch, "0"*64, "2026-11-28T01:00:00Z")
        lock = self.root / ".review-index.lock"
        lock.mkdir()
        with self.assertRaises(FileExistsError):
            refresh(*self.args, "2026-11-28T01:00:00Z")
        lock.rmdir()
        (self.root / INDEX).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            listing(self.root)
        with self.assertRaises(ValueError):
            refresh(*self.args, "2026-11-28T01:00:00Z")
        self.assertEqual((self.root / INDEX).read_bytes(), b"{}")


if __name__ == "__main__":
    unittest.main()
