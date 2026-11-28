import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from trust_maintainer_webhook import CONFIG, FILE, notify, send, load
from trust_maintainer_alerts import observe, acknowledge, listing
from test_trust_maintainer_alerts import receipt


class WebhookTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        self.token = "synthetic-secret"
        self.state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "01"))
        self.transport = Mock(return_value=True)

    def enable(self, url="https://receiver.example/events?key=synthetic-url-secret"):
        (self.root / CONFIG).write_text(json.dumps({"url": url, "bearerToken": self.token}))
        (self.root / CONFIG).chmod(0o600)

    def test_disabled_and_private_config(self):
        self.assertEqual(notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)["status"], "WEBHOOK_DISABLED_NO_CONFIG")
        self.enable()
        (self.root / CONFIG).chmod(0o644)
        with self.assertRaises(ValueError):
            notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)
        for url in ("http://receiver.example/events", "https://user:secret@receiver.example/events", "https://receiver.example/#fragment"):
            self.enable(url)
            with self.assertRaises(ValueError):
                notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)
        self.transport.assert_not_called()
        self.assertFalse((self.root / FILE).exists())

    def test_sanitized_once_per_generation(self):
        self.enable()
        r = notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)
        self.assertEqual(r["status"], "ACCEPTED_BY_ENDPOINT")
        config, payload = self.transport.call_args.args
        self.assertEqual(config["host"], "receiver.example")
        self.assertEqual(payload["event"], "trust-registry.maintenance.alerts")
        self.assertEqual(payload["alerts"], [{"sourceId": "sheca-repository", "kind": "SOURCE_BODY_CHANGED", "message": "source content changed"}])
        for secret in (self.token, "synthetic-url-secret", "private URL"):
            self.assertNotIn(secret, json.dumps(payload))
            self.assertNotIn(secret.encode(), (self.root / FILE).read_bytes())
        state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "03"))
        self.assertEqual(notify(self.root, state, "2026-11-28T09:00:00Z", self.transport)["status"], "NO_NEW_ALERTS")
        acknowledge(self.root, state, listing(state)["stateSHA256"], "sheca-repository:SOURCE_BODY_CHANGED")
        state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "10"))
        self.assertEqual(notify(self.root, state, "2026-11-28T11:00:00Z", self.transport)["status"], "ACCEPTED_BY_ENDPOINT")
        self.assertEqual(self.transport.call_count, 2)

    def test_failure_and_reservation_cooldown(self):
        self.enable()
        def fail(config, payload):
            self.assertEqual(load(self.root)["lastOutcome"], "ATTEMPT_RESERVED")
            return False
        self.assertEqual(notify(self.root, self.state, "2026-11-28T02:00:00Z", fail)["status"], "FAILED_OR_UNCONFIRMED")
        self.assertEqual(notify(self.root, self.state, "2026-11-28T07:59:59Z", self.transport)["status"], "DELIVERY_COOLDOWN_ACTIVE")
        self.transport.assert_not_called()
        self.assertEqual(notify(self.root, self.state, "2026-11-28T08:00:00Z", self.transport)["status"], "ACCEPTED_BY_ENDPOINT")

    def test_https_post_and_rejection(self):
        config = {"host": "receiver.example", "port": 443, "target": "/events", "token": self.token}
        with patch("trust_maintainer_webhook.http.client.HTTPSConnection") as cls:
            conn = cls.return_value
            response = conn.getresponse.return_value
            response.status = 204
            self.assertTrue(send(config, {"event": "example"}))
            self.assertEqual(cls.call_args.args, ("receiver.example",))
            args, kwargs = conn.request.call_args
            self.assertEqual(args, ("POST", "/events"))
            self.assertEqual(json.loads(kwargs["body"]), {"event": "example"})
            self.assertEqual(kwargs["headers"]["Authorization"], "Bearer " + self.token)
            response.status = 302
            self.assertFalse(send(config, {"event": "example"}))
            response.status = 500
            self.assertFalse(send(config, {"event": "example"}))
            response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
