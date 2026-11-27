from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from trust_maintainer import parser, execute
from trust_maintainer_workspace import initialize, read_config, binary_digest, CONFIG


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent = Path(tmp.name)
        self.root = self.parent / "workspace"
        self.binary = self.parent / "trust-registry"
        self.binary.write_bytes(b"synthetic executable bytes")
        self.binary.chmod(0o700)
        self.pin = binary_digest(self.binary)

    def init(self):
        return initialize(self.root, self.binary, self.pin, 168, 1, ["sheca-repository"])

    def test_initialization_and_readonly_info(self):
        r = self.init()
        self.assertEqual(r["status"], "WORKSPACE_CREATED")
        self.assertEqual(read_config(self.root)["binarySHA256"], self.pin)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {CONFIG, "observations", "review-queue"})
        before = (self.root / CONFIG).read_bytes()
        with self.assertRaises(FileExistsError):
            self.init()
        self.assertEqual((self.root / CONFIG).read_bytes(), before)
        info, code = execute(parser().parse_args(["--workspace", str(self.root), "workspace-info"]))
        self.assertEqual(code, 0)
        self.assertFalse(info["schedulerEnabled"])

    def test_check_binding_and_overrides(self):
        self.init()
        args = ["--workspace", str(self.root), "check"]
        with patch("trust_maintainer.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(execute(parser().parse_args(args)), (None, 0))
            run.assert_called_once_with([str(self.binary), "sources", "monitor-run", "--store", str(self.root/"observations"), "--interval", "168h", "--max-fetches", "1", "--id", "sheca-repository"], check=False, timeout=360)
        with self.assertRaises(ValueError):
            execute(parser().parse_args(args + ["--interval", "1h"]))
        self.binary.write_bytes(b"changed")
        with patch("trust_maintainer.subprocess.run") as run:
            with self.assertRaises(ValueError):
                execute(parser().parse_args(args))
            run.assert_not_called()

    def test_status_and_private_directories(self):
        self.init()
        r, code = execute(parser().parse_args(["--workspace", str(self.root), "status"]))
        self.assertEqual(code, 0)
        self.assertEqual(r["batchCount"], 0)
        with self.assertRaises(ValueError):
            execute(parser().parse_args(["--workspace", str(self.root), "status", "--queue", str(self.parent)]))
        (self.root/"review-queue").chmod(0o755)
        with self.assertRaises(ValueError):
            read_config(self.root)

    def test_invalid_config_and_init(self):
        for hours, budget, ids, pin in [(0, 1, ["sheca-repository"], self.pin),
                                        (168, 2, ["sheca-repository"], self.pin),
                                        (168, 1, ["unknown"], self.pin),
                                        (168, 1, ["sheca-repository"], "0"*64)]:
            with self.assertRaises(ValueError):
                initialize(self.root, self.binary, pin, hours, budget, ids)
            self.assertFalse(self.root.exists())
        self.init()
        (self.root / CONFIG).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            read_config(self.root)


if __name__ == "__main__":
    unittest.main()
