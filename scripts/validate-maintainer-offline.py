#!/usr/bin/env python3
"""Offline end-to-end developer gate using actual Go observation bytes.

All HTML is generated from selected research rows, not a live source.
No trust publication, external endpoint, scheduler or network operation.
"""
import argparse
import datetime as dt
import hashlib
from html import escape
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from sheca_source_acceptance import baseline, DEFAULT_BASELINE, read_bounded, MAX_BASELINE
from sheca_source_adapter import HEADER, SECTIONS, MONTHS

SCRIPT = Path(__file__).resolve().with_name("trust_maintainer.py")
SOURCE = "sheca-repository"
T1 = "2026-11-27T00:00:00Z"
T2 = "2026-11-27T01:00:00.000000001Z"
T3 = "2026-11-27T02:00:00Z"
T4 = "2026-11-27T03:00:00Z"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, fail=False):
    completed = subprocess.run([str(x) for x in command], capture_output=True,
                               timeout=60, check=False)
    if fail:
        require(completed.returncode != 0, "expected command rejection")
        return completed.stderr.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise ValueError("offline command failed: " + completed.stderr.decode("utf-8", errors="replace")[:2000])
    value = json.loads(completed.stdout)
    require(isinstance(value, dict), "expected JSON object")
    return value


def fixture(catalog, changed=False):
    sections = {v: [] for v in SECTIONS.values()}
    first_root = None
    for e in catalog["entries"]:
        section = "DISUSE" if e["publishedStatus"] == "DISUSE" else e["publishedRole"]
        label = e["label"]
        if section == "ROOT" and first_root is None:
            first_root = e["publishedSHA1"]
            if changed:
                label += " synthetic change"
        d = dt.date.fromisoformat(e["publishedValidUntil"])
        month = next(name for name, n in MONTHS.items() if n == d.month)
        fields = (label, e["publishedSHA1"], f"{month} {d.day}, {d.year}")
        sections[section].append("<tr>" + "".join("<td>"+escape(s)+"</td>" for s in fields)
                                 + '<td><a href="/synthetic.pem">PEM</a></td></tr>')
    require(first_root is not None and all(sections.values()), "baseline lacks required sections")
    return "".join("<h3>"+escape(heading)+"</h3><table><tr>"
                   +"".join("<th>"+escape(h)+"</th>" for h in HEADER)+"</tr>"
                   +"".join(sections[section])+"</table>" for heading, section in SECTIONS.items())


def exercise(binary, consumer, root):
    def go(*args, fail=False):
        return run([binary, "sources", *args], fail=fail)

    def maint(*args, use_workspace=False, fail=False):
        command = [sys.executable, "-B", SCRIPT]
        if use_workspace:
            command += ["--workspace", str(workspace)]
        return run(command + list(args), fail=fail)

    # A default binary must reject monitor-list for the intended reason,
    # rather than merely failing to start.
    err = run([consumer, "sources", "monitor-list"], fail=True)
    require("source-built maintainer CLI" in err, "wrong consumer rejection reason")
    workspace = root / "workspace"
    catalog = baseline(read_bounded(DEFAULT_BASELINE, MAX_BASELINE))
    init = maint("workspace-init", "--binary", binary, "--binary-sha256", sha(binary),
                 "--interval-hours", "168", "--max-fetches", "1", "--id", SOURCE, use_workspace=True)
    require(init["status"] == "WORKSPACE_CREATED", "workspace initialization failed")
    store = workspace / "observations"
    originals = []
    pins = []
    for i, (at, change) in enumerate(((T1, False), (T2, True))):
        html = root / f"synthetic-{i}.html"
        html.write_text(fixture(catalog, change), encoding="utf-8")
        original = root / f"observation-{i}.json"
        receipt = go("monitor-local", "--id", SOURCE, "--recorded-at", at, "--out", original, html)
        pin = sha(original)
        require(receipt["observationSHA256"] == pin and receipt["mode"] == "LOCAL_INPUT",
                "Go original identity mismatch")
        stored = go("monitor-add", "--store", store, "--sha256", pin, original)
        require(stored["count"] == i+1, "unexpected Go observation count")
        replay = go("monitor-verify", "--store", store, "--mode", "LOCAL_INPUT", "--id", SOURCE, "--sha256", pin)
        require(replay["observationSHA256"] == pin, "Go replay mismatch")
        originals.append(original)
        pins.append(pin)
    history = go("monitor-history", "--store", store, "--mode", "LOCAL_INPUT", "--id", SOURCE)
    require([r["observationSHA256"] for r in history["observations"]] == pins, "Go history mismatch")
    cross = maint("acceptance", "--sha256", pins[0], originals[0])
    require(cross["counts"]["matching"] == len(catalog["entries"])
            and cross["counts"]["baselineRows"] == len(catalog["entries"])
            and cross["unlistedFingerprintClaimCount"] == 0
            and cross["liveProfileAccepted"] is False, "real baseline / synthetic HTML cross-check mismatch")
    pair = ["--previous-sha256", pins[0], "--current-sha256", pins[1], *originals]
    preview = maint("plan", *pair)
    tasks = preview["batch"]["tasks"]
    require({x["kind"] for x in tasks} == {"SINGLE_CLAIM_FIELDS_CHANGED", "RAW_SOURCE_BODY_REVIEW"}
            and len(tasks) == 2, "unexpected cross-language review tasks")
    pin = preview["batchSHA256"]
    bound = ["--batch-sha256", pin, *pair]
    maint("enqueue", "--batch-sha256", "0"*64, *pair, "--at", T3, use_workspace=True, fail=True)
    require(not any((workspace / "review-queue").iterdir()), "wrong pin wrote queue")
    queued = maint("enqueue", *bound, "--at", T3, use_workspace=True)
    require(queued["status"] == "WRITE_COMMITTED_INDEX_REFRESHED", "enqueue failed")
    queued = maint("enqueue", *bound, "--at", T3, use_workspace=True)
    require(queued["committed"]["status"] == "EXACT_BATCH_REUSED", "enqueue not idempotent")
    state = maint("status", use_workspace=True)
    require(state["matching"] == 2, "open task index mismatch")
    task = tasks[0]["taskId"]
    done = maint("record", *bound, "--task-id", task, "--expected-head", "EMPTY",
                 "--action", "REVIEW_COMPLETE", "--at", T4, "--reviewer", "synthetic-test",
                 "--note", "offline developer test only", use_workspace=True)
    require(done["status"] == "WRITE_COMMITTED_INDEX_REFRESHED", "record failed")
    reviewed = maint("history", *bound, "--task-id", task, use_workspace=True)
    require(reviewed["status"] == "REVIEW_COMPLETE" and reviewed["eventCount"] == 1
            and reviewed["headSHA256"] == done["committed"]["headSHA256"], "disposition replay mismatch")
    require(maint("status", use_workspace=True)["matching"] == 1, "closed task still open")
    # Confirm this entirely offline path did not authorize trust or real-source acceptance.
    require(reviewed["trustStatus"] == "NOT_ESTABLISHED" and not reviewed["liveProfileAccepted"],
            "source task improperly established trust")
    return {"status": "OFFLINE_MAINTAINER_WORKFLOW_PASSED", "observationMode": "LOCAL_INPUT",
            "baselineRows": len(catalog["entries"]), "observations": 2, "reviewTasks": 2,
            "completedTasks": 1, "liveProfileAccepted": False, "trustStatus": "NOT_ESTABLISHED"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--maintainer", required=True, type=Path)
    p.add_argument("--consumer", required=True, type=Path)
    args = p.parse_args()
    os.umask(0o077)
    try:
        binary, consumer = args.maintainer.resolve(strict=True), args.consumer.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="trust-offline-maintainer-") as directory:
            result = exercise(binary, consumer, Path(directory))
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
        print("Offline maintainer acceptance: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
