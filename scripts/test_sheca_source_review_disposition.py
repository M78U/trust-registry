from pathlib import Path
import tempfile
import unittest

from sheca_source_review_disposition import append, inspect, canonical
from sheca_source_review_queue import persist
from test_sheca_source_review_queue import batch
from test_sheca_source_diff import page


class DispositionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.batch = batch(page(), page(root=[("New", "d"*40)]))
        self.pin = persist(self.root, self.batch)["batchSHA256"]
        self.task = self.batch["tasks"][0]["taskId"]
        self.args = (self.root, self.batch, self.pin, self.task)
        self.path = self.root / (self.batch["batchId"]+".dispositions") / self.task

    def record(self, head, action, at):
        return append(*self.args, head, action, at, "maintainer", "Reviewed source evidence")

    def test_transition_and_chain(self):
        self.assertEqual(inspect(*self.args)["headSHA256"], "EMPTY")
        a = self.record("EMPTY", "NEEDS_INVESTIGATION", "2026-11-28T01:00:00Z")
        first = (self.path/"0001.json").read_bytes()
        b = self.record(a["headSHA256"], "REVIEW_COMPLETE", "2026-11-28T02:00:00Z")
        self.assertEqual(b["status"], "REVIEW_COMPLETE")
        c = self.record(b["headSHA256"], "REOPENED", "2026-11-28T03:00:00Z")
        self.assertEqual(c["status"], "PENDING_HUMAN_REVIEW")
        self.assertEqual(c["eventCount"], 3)
        self.assertEqual(c, inspect(*self.args))
        self.assertEqual(first, (self.path/"0001.json").read_bytes())
        self.assertEqual(c["events"][1]["previousSHA256"], a["headSHA256"])
        self.assertEqual(c["trustStatus"], "NOT_ESTABLISHED")

    def test_stale_invalid_and_wrong_task(self):
        with self.assertRaises(ValueError):
            self.record("EMPTY", "REOPENED", "2026-11-28T01:00:00Z")
        a = self.record("EMPTY", "REVIEW_COMPLETE", "2026-11-28T01:00:00Z")
        with self.assertRaises(ValueError):
            self.record("EMPTY", "REOPENED", "2026-11-28T02:00:00Z")
        with self.assertRaises(ValueError):
            self.record(a["headSHA256"], "REOPENED", "2026-11-28T01:00:00Z")
        with self.assertRaises(ValueError):
            self.record(a["headSHA256"], "REVIEW_COMPLETE", "2026-11-28T02:00:00Z")
        with self.assertRaises(ValueError):
            inspect(self.root, self.batch, self.pin, "0"*64)
        with self.assertRaises(ValueError):
            inspect(self.root, self.batch, "0"*64, self.task)

    def test_tamper_gap_and_busy(self):
        a = self.record("EMPTY", "NEEDS_INVESTIGATION", "2026-11-28T01:00:00Z")
        b = self.record(a["headSHA256"], "REVIEW_COMPLETE", "2026-11-28T02:00:00Z")
        lock = self.path / ".lock"
        lock.mkdir()
        with self.assertRaises(ValueError):
            inspect(*self.args)
        with self.assertRaises(FileExistsError):
            self.record(b["headSHA256"], "REOPENED", "2026-11-28T03:00:00Z")
        lock.rmdir()
        first = self.path / "0001.json"
        original = first.read_bytes()
        first.unlink()
        with self.assertRaises(ValueError):
            inspect(*self.args)
        first.write_bytes(original)
        changed = dict(a["events"][0], note="changed")
        first.write_bytes(canonical(changed))
        with self.assertRaises(ValueError):
            inspect(*self.args)

    def test_batch_and_note_boundaries(self):
        with self.assertRaises(ValueError):
            append(*self.args, "EMPTY", "NEEDS_INVESTIGATION", "2026-11-28T01:00:00Z", "maintainer", " ")
        with self.assertRaises(ValueError):
            append(*self.args, "EMPTY", "NEEDS_INVESTIGATION", "2026-11-28T01:00:00Z", "maintainer", "x"*1025)
        self.assertEqual(inspect(*self.args)["eventCount"], 0)
        (self.root/(self.batch["batchId"]+".json")).write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            self.record("EMPTY", "NEEDS_INVESTIGATION", "2026-11-28T01:00:00Z")


if __name__ == "__main__":
    unittest.main()
