"""Generate a manual macOS LaunchAgent and retain one local check receipt."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile

from sheca_source_adapter import digest, unique_object
from sheca_source_review_queue import canonical, private_root
import trust_maintainer_workspace as workspace
import trust_maintainer_alerts as alerts

LAST = "last-scheduled-check.json"
MAX_REPORT = 256 << 10
MAX_OUTPUT = 128 << 10
ERRORS = (ValueError, TypeError, KeyError, OSError, RecursionError)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def plist(root, hour, minute, script, python, notify_webhook=False):
    if not root.is_absolute() or not script.is_absolute() or not python.is_absolute():
        raise ValueError("absolute workspace, script and interpreter paths required")
    if type(hour) is not int or type(minute) is not int or not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError("invalid daily local time")
    workspace.read_config(root)
    if not script.is_file() or not python.is_file():
        raise ValueError("trusted script and Python interpreter must exist")
    root = root.resolve(strict=True)
    label = "com.m78u.trust-registry.maintainer." + digest(os.fsencode(root))[:16]
    arguments = [str(python), "-E", "-s", "-B", str(script), "--workspace", str(root), "scheduled-check"]
    if notify_webhook:
        arguments.append("--notify-webhook")
    return plistlib.dumps({
        "Label": label,
        "ProgramArguments": arguments,
        "WorkingDirectory": str(root),
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        "RunAtLoad": False,
        "KeepAlive": False,
        "Umask": 63,
        "ProcessType": "Background",
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }, sort_keys=True)


def write_latest(root, report):
    raw = canonical(report)
    if len(raw) > MAX_REPORT:
        raise ValueError("scheduled report size limit")
    fd, temp = tempfile.mkstemp(prefix=".scheduled-check-pending-", dir=root)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, root / LAST)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def last(root):
    private_root(root)
    path = root / LAST
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"status": "NO_SCHEDULED_CHECK_RECEIPT", "trustStatus": "NOT_ESTABLISHED"}
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= MAX_REPORT:
        raise ValueError("invalid private scheduled receipt")
    with path.open("rb") as f:
        if not os.path.samestat(info, os.fstat(f.fileno())):
            raise ValueError("scheduled receipt changed while opening")
        raw = f.read(MAX_REPORT + 1)
    if len(raw) > MAX_REPORT:
        raise ValueError("scheduled receipt size limit")
    r = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(r, dict) or r.get("schemaVersion") != "1" or r.get("trustStatus") != "NOT_ESTABLISHED" or canonical(r) != raw:
        raise ValueError("invalid scheduled receipt")
    return r


def scheduled_check(root, command_builder):
    """One collection pass; no semantic parsing, enqueue or approval."""
    with workspace.check_update_lock(root):
        # Reconcile any prior committed receipt before replacing it.
        alerts.observe(root, last(root))
        result = {"schemaVersion": "1", "startedAt": now(), "configurationSHA256": None,
                  "status": "CHECK_FAILED", "exitCode": 1, "monitorReport": None,
                  "detail": None, "liveProfileAccepted": False,
                  "trustStatus": "NOT_ESTABLISHED"}
        try:
            config = workspace.read_config(root)
            result["configurationSHA256"] = digest(canonical(config))
            args = argparse.Namespace(operation="check", binary=None, store=None,
                                      interval=None, max_fetches=None, id=None)
            workspace.apply(root, args)
            command = command_builder(args)
            # Output is from the explicitly bound trusted Go CLI. Retain
            # only bounded parsed output; do not persist arbitrary stderr.
            completed = subprocess.run(command, check=False, timeout=360, capture_output=True)
            if len(completed.stdout) > MAX_OUTPUT:
                raise ValueError("Go report exceeds retained output limit")
            report = json.loads(completed.stdout, object_pairs_hook=unique_object)
            if not isinstance(report, dict) or report.get("trustStatus") != "NOT_ESTABLISHED" or report.get("sourceAuthentication") != "NOT_ESTABLISHED" or not isinstance(report.get("rows"), list):
                raise ValueError("unexpected Go monitor report")
            result["monitorReport"] = report
            result["exitCode"] = completed.returncode
            result["status"] = "CHECK_COMPLETED" if completed.returncode == 0 else "CHECK_INCOMPLETE"
            if len(canonical(result)) > MAX_REPORT - 2048:
                result["monitorReport"] = None
                raise ValueError("canonical Go report exceeds retained receipt limit")
        except subprocess.TimeoutExpired:
            result["status"] = "CHECK_FAILED"
            result["exitCode"] = 1
            result["detail"] = "CHECK_TIMEOUT_INSPECT_LOCKS"
        except ERRORS:
            result["status"] = "CHECK_FAILED"
            result["exitCode"] = 1
            result["monitorReport"] = None
            result["detail"] = "CONFIG_EXECUTION_OR_REPORT_REVIEW_REQUIRED"
        result["finishedAt"] = now()
        write_latest(root, result)
        alerts.observe(root, result)
        return result, 0 if result["exitCode"] == 0 else 1
