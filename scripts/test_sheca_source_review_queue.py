import tempfile
from pathlib import Path
import unittest

from sheca_source_review_queue import prepare, persist, verify, canonical
from test_sheca_source_diff import capture, page


def batch(a, b):
    return prepare(*capture(a), *capture(b, "2026-11-28T00:00:00Z"))


class ReviewQueueTest(unittest.TestCase):
    def test_changes_and_raw_review(self):
        a = page()
        b = page(root=[("New root", "d"*40)])
        r = batch(a, b)
        self.assertEqual({t["kind"] for t in r["tasks"]},
                         {"NEW_PUBLISHED_FINGERPRINT_CLAIM", "PUBLISHED_FINGERPRINT_NOT_OBSERVED", "RAW_SOURCE_BODY_REVIEW"})
        self.assertEqual(r["taskCount"], 3)
        self.assertEqual(r, batch(a, b))
        self.assertEqual(len({t["taskId"] for t in r["tasks"]}), 3)
        self.assertTrue(all(t["status"] == "PENDING_HUMAN_REVIEW" for t in r["tasks"]))
        self.assertNotIn(b"/test.pem", canonical(r))
        self.assertFalse(r["liveProfileAccepted"])

    def test_raw_only_and_unchanged_ambiguity(self):
        a = page()
        self.assertEqual(batch(a, a)["taskCount"], 0)
        self.assertEqual([t["kind"] for t in batch(a, "<div>"+a+"</div>")["tasks"]],
                         ["RAW_SOURCE_BODY_REVIEW"])
        a = page(root=[("Root", "a"*40), ("Alias", "a"*40)])
        self.assertEqual([t["kind"] for t in batch(a, a)["tasks"]],
                         ["AMBIGUOUS_PUBLISHED_SHA1_REVIEW"])
        r = batch(page(), page(root=[("Root", "a"*40), ("Root", "A"*40)]))
        self.assertIn("EXACT_DUPLICATE_COUNT_REVIEW", {t["kind"] for t in r["tasks"]})

    def test_no_overwrite_and_replay(self):
        r = batch(page(), page(root=[("New", "d"*40)]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            first = persist(root, r)
            self.assertEqual(first["status"], "BATCH_CREATED")
            self.assertEqual(persist(root, r)["status"], "EXACT_BATCH_REUSED")
            self.assertEqual(verify(root, r, first["batchSHA256"])["status"], "PINNED_BATCH_REPLAYED")
            with self.assertRaises(ValueError):
                verify(root, r, "0"*64)
            path = root / (r["batchId"]+".json")
            path.write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                persist(root, r)
            with self.assertRaises(ValueError):
                verify(root, r, first["batchSHA256"])
            self.assertEqual(path.read_bytes(), b"corrupt")

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            batch(page(), "<html>challenge</html>")
        a = capture(page())
        with self.assertRaises(ValueError):
            prepare(*a, *a)


if __name__ == "__main__":
    unittest.main()
