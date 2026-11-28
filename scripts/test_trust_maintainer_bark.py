import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from trust_maintainer_bark import KEY, FILE, notify, send, load
from trust_maintainer_alerts import observe, acknowledge, listing
from test_trust_maintainer_alerts import receipt


class BarkTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        self.key = "synthetic-key-only"
        self.state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "01"))
        self.transport = Mock(return_value=True)

    def enable(self):
        (self.root / KEY).write_text(self.key)
        (self.root / KEY).chmod(0o600)

    def test_disabled_and_private_key(self):
        self.assertEqual(notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)["status"], "BARK_DISABLED_NO_KEY")
        self.enable()
        (self.root / KEY).chmod(0o644)
        with self.assertRaises(ValueError):
            notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)
        self.transport.assert_not_called()
        self.assertFalse((self.root / FILE).exists())

    def test_sanitized_once_per_generation(self):
        self.enable()
        r = notify(self.root, self.state, "2026-11-28T02:00:00Z", self.transport)
        self.assertEqual(r["status"], "ACCEPTED_BY_RELAY")
        self.transport.assert_called_once_with(self.key, "Maintenance review required:\nsheca-repository: source content changed")
        self.assertNotIn(self.key.encode(), (self.root / FILE).read_bytes())
        state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "03"))
        self.assertEqual(notify(self.root, state, "2026-11-28T09:00:00Z", self.transport)["status"], "NO_NEW_ALERTS")
        acknowledge(self.root, state, listing(state)["stateSHA256"], "sheca-repository:SOURCE_BODY_CHANGED")
        state = observe(self.root, receipt("BODY_CHANGED_REVIEW_REQUIRED", "10"))
        self.assertEqual(notify(self.root, state, "2026-11-28T11:00:00Z", self.transport)["status"], "ACCEPTED_BY_RELAY")
        self.assertEqual(self.transport.call_count, 2)

    def test_failure_and_reservation_cooldown(self):
        self.enable()
        def fail(key, body):
            self.assertEqual(load(self.root)["lastOutcome"], "ATTEMPT_RESERVED")
            return False
        self.assertEqual(notify(self.root, self.state, "2026-11-28T02:00:00Z", fail)["status"], "FAILED_OR_UNCONFIRMED")
        self.assertEqual(notify(self.root, self.state, "2026-11-28T07:59:59Z", self.transport)["status"], "DELIVERY_COOLDOWN_ACTIVE")
        self.transport.assert_not_called()
        self.assertEqual(notify(self.root, self.state, "2026-11-28T08:00:00Z", self.transport)["status"], "ACCEPTED_BY_RELAY")

    def test_fixed_post_and_rejection(self):
        with patch("trust_maintainer_bark.http.client.HTTPSConnection") as cls:
            conn = cls.return_value
            response = conn.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "identity"
            response.read.return_value = b'{"code":200}'
            self.assertTrue(send(self.key, "test"))
            self.assertEqual(cls.call_args.args, ("api.day.app",))
            args, kwargs = conn.request.call_args
            self.assertEqual(args, ("POST", "/push"))
            self.assertEqual(json.loads(kwargs["body"])["device_key"], self.key)
            response.read.return_value = b'{"code":400}'
            self.assertFalse(send(self.key, "test"))
            response.status = 302
            self.assertFalse(send(self.key, "test"))
            response.status = 200
            response.read.return_value = b"x"*4097
            self.assertFalse(send(self.key, "test"))


if __name__ == "__main__":
    unittest.main()
