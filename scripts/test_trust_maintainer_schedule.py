import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from trust_maintainer import parser, execute
from trust_maintainer_workspace import initialize, binary_digest, LOCK
from trust_maintainer_schedule import LAST, last


class ScheduleTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        parent = Path(tmp.name)
        self.root = parent / "workspace"
        binary = parent / "trust-registry"
        binary.write_bytes(b"synthetic executable")
        binary.chmod(0o700)
        initialize(self.root, binary, binary_digest(binary), 168, 1, ["sheca-repository"])
        self.binary = binary
        self.args = ["--workspace", str(self.root)]

    def test_plist_is_read_only(self):
        data, code = execute(parser().parse_args(self.args + ["schedule-plist", "--hour", "9", "--minute", "15"]))
        self.assertEqual(code, 0)
        job = plistlib.loads(data)
        self.assertEqual(job["StartCalendarInterval"], {"Hour": 9, "Minute": 15})
        self.assertEqual(job["ProgramArguments"][-1], "scheduled-check")
        self.assertFalse(job["RunAtLoad"])
        self.assertFalse(job["KeepAlive"])
        self.assertEqual(job["Umask"], 63)
        self.assertFalse((self.root / LAST).exists())
        with self.assertRaises(ValueError):
            execute(parser().parse_args(self.args + ["schedule-plist", "--hour", "24", "--minute", "0"]))

    def test_success_and_incomplete_receipts_replace(self):
        self.assertEqual(last(self.root)["status"], "NO_SCHEDULED_CHECK_RECEIPT")
        report = {"status": "COMPLETED", "rows": [], "trustStatus": "NOT_ESTABLISHED", "sourceAuthentication": "NOT_ESTABLISHED"}
        with patch("trust_maintainer_schedule.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(report).encode(), b"")) as run:
            r, code = execute(parser().parse_args(self.args + ["scheduled-check"]))
            self.assertEqual(code, 0)
            self.assertEqual(r["monitorReport"], report)
            self.assertEqual(r, last(self.root))
            run.assert_called_once_with([str(self.binary), "sources", "monitor-run", "--store", str(self.root/"observations"), "--interval", "168h", "--max-fetches", "1", "--id", "sheca-repository"], check=False, timeout=360, capture_output=True)
        report["status"] = "INCOMPLETE"
        with patch("trust_maintainer_schedule.subprocess.run", return_value=subprocess.CompletedProcess([], 1, json.dumps(report).encode(), b"private error")):
            r, code = execute(parser().parse_args(self.args + ["scheduled-check"]))
            self.assertEqual(code, 1)
            self.assertEqual(r["status"], "CHECK_INCOMPLETE")
            self.assertEqual(r, last(self.root))
            self.assertNotIn(b"private error", (self.root / LAST).read_bytes())
        self.assertFalse((self.root / LOCK).exists())

    def test_invalid_output_timeout_and_binary_change(self):
        with patch("trust_maintainer_schedule.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"bad", b"")):
            r, code = execute(parser().parse_args(self.args + ["scheduled-check"]))
            self.assertEqual(code, 1)
            self.assertEqual(r["status"], "CHECK_FAILED")
        with patch("trust_maintainer_schedule.subprocess.run", side_effect=subprocess.TimeoutExpired([], 360)):
            r, code = execute(parser().parse_args(self.args + ["scheduled-check"]))
            self.assertEqual(code, 1)
            self.assertEqual(r["detail"], "CHECK_TIMEOUT_INSPECT_LOCKS")
        self.binary.write_bytes(b"replaced")
        with patch("trust_maintainer_schedule.subprocess.run") as run:
            r, code = execute(parser().parse_args(self.args + ["scheduled-check"]))
            self.assertEqual(code, 1)
            run.assert_not_called()
        self.assertEqual(r, last(self.root))

    def test_busy_workspace_does_not_start_or_overwrite(self):
        (self.root / LOCK).mkdir()
        with patch("trust_maintainer_schedule.subprocess.run") as run:
            with self.assertRaises(FileExistsError):
                execute(parser().parse_args(self.args + ["scheduled-check"]))
            run.assert_not_called()
        self.assertFalse((self.root / LAST).exists())


if __name__ == "__main__":
    unittest.main()
