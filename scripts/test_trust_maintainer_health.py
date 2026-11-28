import json
from pathlib import Path
import tempfile
import unittest

from sheca_source_adapter import digest
from sheca_source_review_queue import canonical
from trust_maintainer_workspace import initialize, binary_digest, LOCK
from trust_maintainer_schedule import write_latest
from trust_maintainer_alerts import observe
from trust_maintainer_health import health
from trust_maintainer_webhook import CONFIG


class HealthTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent = Path(tmp.name)
        self.root = self.parent / "workspace"
        self.binary = self.parent / "trust-registry"
        self.binary.write_bytes(b"synthetic executable")
        self.binary.chmod(0o700)
        self.pin = initialize(self.root, self.binary, binary_digest(self.binary), 168, 1, ["sheca-repository"])["configurationSHA256"]

    def receipt(self, finished="2026-11-28T01:00:00Z", config_pin=None):
        r = {"schemaVersion": "1", "status": "CHECK_COMPLETED", "exitCode": 0,
             "startedAt": "2026-11-28T00:00:00Z", "finishedAt": finished,
             "configurationSHA256": config_pin or self.pin,
             "monitorReport": {"trustStatus": "NOT_ESTABLISHED", "sourceAuthentication": "NOT_ESTABLISHED", "rows": []},
             "trustStatus": "NOT_ESTABLISHED"}
        write_latest(self.root, r)
        return r

    def report(self, at="2026-11-28T02:00:00Z"):
        return health(self.root, at)

    def component(self, report, key):
        return next(c for c in report["checks"] if c["check"] == key)

    def test_missing_then_fresh_and_readonly(self):
        self.assertEqual(self.report()["status"], "OPERATOR_REVIEW_REQUIRED")
        r = self.receipt()
        self.assertFalse(self.component(self.report(), "alerts")["receiptReconciled"])
        observe(self.root, r)
        before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        result = self.report()
        self.assertEqual(result["status"], "LOCAL_CHECKS_OK")
        self.assertEqual(result["schedulerInstallation"], "NOT_CHECKED")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()})
        self.assertEqual(self.component(result, "reviewIndex")["coverage"], "EXPLICITLY_REFRESHED_BATCHES_ONLY")

    def test_old_future_and_config_mismatch(self):
        r = self.receipt(config_pin="0"*64)
        observe(self.root, r)
        result = self.report("2026-11-30T00:00:00Z")
        self.assertEqual(set(self.component(result, "scheduledReceipt")["reasons"]),
                         {"RECEIPT_TOO_OLD", "CURRENT_CONFIGURATION_NOT_CONFIRMED"})
        self.assertEqual(self.component(self.report("2026-11-28T00:30:00Z"), "scheduledReceipt")["status"], "REVIEW_REQUIRED")

    def test_binary_lock_and_webhook_redaction(self):
        self.binary.write_bytes(b"changed")
        (self.root / LOCK).mkdir()
        cfg = self.root / CONFIG
        cfg.write_text(json.dumps({"url": "https://receiver.example/path?secret=private-secret", "bearerToken": "secret-token"}))
        cfg.chmod(0o600)
        r = self.report()
        self.assertEqual(self.component(r, "cliBinding")["status"], "REVIEW_REQUIRED")
        self.assertEqual(self.component(r, "workspaceLock")["status"], "REVIEW_REQUIRED")
        self.assertEqual(self.component(r, "webhook")["status"], "CONFIGURED_NOT_CONTACTED")
        for secret in ("private-secret", "secret-token", "receiver.example"):
            self.assertNotIn(secret, json.dumps(r))
        cfg.chmod(0o644)
        self.assertEqual(self.component(self.report(), "webhook")["status"], "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
