import tempfile
from pathlib import Path
import unittest

from trust_maintainer_alerts import observe, listing, acknowledge, load, FILE


def receipt(status, time, source="sheca-repository"):
    return {"status": "CHECK_INCOMPLETE" if status == "SOURCE_FETCH_FAILED" else "CHECK_COMPLETED",
            "finishedAt": f"2026-11-28T{time}:00:00Z",
            "monitorReport": {"trustStatus": "NOT_ESTABLISHED", "sourceAuthentication": "NOT_ESTABLISHED",
                              "rows": [{"source": {"id": source}, "status": status, "detail": "private URL"}]}}


class AlertTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)

    def test_change_retained_and_replay_idempotent(self):
        a = receipt("BODY_CHANGED_REVIEW_REQUIRED", "01")
        first = observe(self.root, a)
        self.assertEqual(first, observe(self.root, a))
        state = observe(self.root, receipt("BODY_UNCHANGED", "02"))
        result = listing(state)
        self.assertEqual(result["pendingCount"], 1)
        self.assertEqual(result["alerts"][0]["occurrences"], 1)
        self.assertNotIn(b"private URL", (self.root/FILE).read_bytes())
        state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "03"))
        self.assertEqual(listing(state)["alerts"][0]["occurrences"], 2)
        with self.assertRaises(ValueError):
            acknowledge(self.root, state, result["stateSHA256"], result["alerts"][0]["alertId"])
        result = listing(state)
        self.assertEqual(acknowledge(self.root, state, result["stateSHA256"], result["alerts"][0]["alertId"])["pendingCount"], 0)
        self.assertEqual(listing(observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "03")))["pendingCount"], 0)

    def test_failure_streak_cooldown_and_recovery(self):
        state = observe(self.root, receipt("SOURCE_FETCH_FAILED", "01"))
        self.assertEqual(listing(state)["pendingCount"], 0)
        observe(self.root, receipt("RETRY_COOLDOWN_ACTIVE", "02"))
        state = observe(self.root, receipt("SOURCE_FETCH_FAILED", "03"))
        self.assertEqual(listing(state)["alerts"][0]["kind"], "REPEATED_FETCH_FAILURE")
        state = observe(self.root, receipt("BODY_UNCHANGED", "04"))
        self.assertEqual(state["failureStreaks"], {})
        self.assertEqual(listing(state)["pendingCount"], 1)

    def test_local_and_workspace_failures(self):
        observe(self.root, receipt("LOCAL_STATE_REVIEW_REQUIRED", "01"))
        state = observe(self.root, {"status": "CHECK_FAILED", "finishedAt": "2026-11-28T02:00:00Z", "detail": "private"})
        self.assertEqual({a["kind"] for a in listing(state)["alerts"]}, {"SOURCE_STATE_REVIEW", "WORKSPACE_CHECK_FAILED"})

    def test_corrupt_and_unknown_refused(self):
        observe(self.root, receipt("BODY_UNCHANGED", "01"))
        original = (self.root/FILE).read_bytes()
        with self.assertRaises(ValueError):
            observe(self.root, receipt("UNKNOWN", "02"))
        self.assertEqual((self.root/FILE).read_bytes(), original)
        (self.root/FILE).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            load(self.root)


if __name__ == "__main__":
    unittest.main()
