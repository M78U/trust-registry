from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from trust_maintainer import parser, execute
from trust_maintainer_workspace import initialize, read_config, binary_digest, CONFIG, HISTORY, LOCK, update, archived


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
        self.assertEqual(info["schedulerInstallation"], "NOT_CHECKED")

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


    def test_reviewed_update_preserves_state_and_archives(self):
        old = self.init()
        old_pin = old["configurationSHA256"]
        previous = (self.root / CONFIG).read_bytes()
        (self.root / "observations" / "marker").write_bytes(b"keep")
        (self.root / "review-queue" / "marker").write_bytes(b"keep")
        new = self.parent / "trust-registry-v2"
        new.write_bytes(b"new synthetic executable")
        new.chmod(0o700)
        pin = binary_digest(new)
        result = update(self.root, old_pin, new, pin, 24, 2, ["sheca-repository", "satl-list"])
        self.assertEqual(result["status"], "WORKSPACE_CONFIGURATION_UPDATED")
        self.assertEqual(result["previousConfigurationSHA256"], old_pin)
        self.assertEqual((self.root / HISTORY / (old_pin+".json")).read_bytes(), previous)
        self.assertEqual(archived(self.root, old_pin)["configuration"], old["configuration"])
        self.assertEqual((self.root / "observations" / "marker").read_bytes(), b"keep")
        self.assertEqual((self.root / "review-queue" / "marker").read_bytes(), b"keep")
        with self.assertRaises(ValueError):
            update(self.root, old_pin, new, pin, 24, 2, ["sheca-repository", "satl-list"])
        new_pin = result["configurationSHA256"]
        same = update(self.root, new_pin, new, pin, 24, 2, ["sheca-repository", "satl-list"])
        self.assertEqual(same["status"], "WORKSPACE_CONFIGURATION_UNCHANGED")
        self.assertEqual(len(list((self.root / HISTORY).iterdir())), 1)
        with patch("trust_maintainer.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(execute(parser().parse_args(["--workspace", str(self.root), "check"])), (None, 0))
            run.assert_called_once_with([str(new), "sources", "monitor-run", "--store", str(self.root/"observations"),
                                         "--interval", "24h", "--max-fetches", "2", "--id", "sheca-repository",
                                         "--id", "satl-list"], check=False, timeout=360)

    def test_conflicts_and_shared_lock(self):
        old = self.init()
        old_pin = old["configurationSHA256"]
        initial = (self.root / CONFIG).read_bytes()
        args = (self.root, old_pin, self.binary, self.pin, 24, 1, ["sheca-repository"])
        with self.assertRaises(ValueError):
            update(self.root, old_pin, self.binary, "0"*64, 24, 1, ["sheca-repository"])
        self.assertFalse((self.root / HISTORY).exists())
        lock = self.root / LOCK
        lock.mkdir()
        with self.assertRaises(FileExistsError):
            update(*args)
        with patch("trust_maintainer.subprocess.run") as run:
            with self.assertRaises(FileExistsError):
                execute(parser().parse_args(["--workspace", str(self.root), "check"]))
            run.assert_not_called()
        lock.rmdir()
        self.assertEqual((self.root / CONFIG).read_bytes(), initial)
        (self.root / HISTORY).mkdir(mode=0o700)
        path = self.root / HISTORY / (old_pin+".json")
        path.write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            update(*args)
        self.assertEqual(path.read_bytes(), b"corrupt")
        self.assertEqual((self.root / CONFIG).read_bytes(), initial)
        self.assertFalse(lock.exists())

    def test_interrupted_archive_reused_and_explicit_restore(self):
        old = self.init()
        pin = old["configurationSHA256"]
        from trust_maintainer_workspace import archive_configuration
        archive_configuration(self.root, old["configuration"])
        update(self.root, pin, self.binary, self.pin, 24, 1, ["satl-list"])
        current = read_config(self.root)
        from sheca_source_adapter import digest
        from sheca_source_review_queue import canonical
        current_pin = digest(canonical(current))
        result, code = execute(parser().parse_args(["--workspace", str(self.root), "workspace-update",
            "--expected-config-sha256", current_pin, "--binary", str(self.binary), "--binary-sha256", self.pin,
            "--interval-hours", "168", "--max-fetches", "1", "--id", "sheca-repository"]))
        self.assertEqual(code, 0)
        self.assertEqual(result["configurationSHA256"], pin)
        r, code = execute(parser().parse_args(["--workspace", str(self.root), "workspace-archive", "--config-sha256", current_pin]))
        self.assertEqual(code, 0)
        self.assertEqual(r["configuration"], current)


if __name__ == "__main__":
    unittest.main()
