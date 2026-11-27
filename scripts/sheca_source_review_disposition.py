#!/usr/bin/env python3
"""Append private human source-review dispositions, not trust approvals."""
import argparse
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from sheca_source_adapter import digest, unique_object
from sheca_source_diff import read_observation, time_key
from sheca_source_review_queue import canonical, prepare, private_root, verify

MAX_EVENTS = 32
MAX_EVENT_BYTES = 16384
ACTIONS = ("NEEDS_INVESTIGATION", "REVIEW_COMPLETE", "REOPENED")
HEX = re.compile(r"[0-9a-f]{64}")


def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
        raise ValueError("explicit UTC RFC3339 time required")
    dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return time_key(value)


def human_text(value, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or not all(c.isprintable() for c in value):
        raise ValueError("nonempty bounded printable human text required")
    return value


def task_of(batch, task_id):
    if not HEX.fullmatch(task_id):
        raise ValueError("invalid task ID")
    matches = [t for t in batch["tasks"] if t["taskId"] == task_id]
    if len(matches) != 1:
        raise ValueError("task not in verified batch")
    return matches[0]


def next_status(status, action):
    if action == "REOPENED" and status == "REVIEW_COMPLETE":
        return "PENDING_HUMAN_REVIEW"
    if status in ("PENDING_HUMAN_REVIEW", "NEEDS_INVESTIGATION") and action in ("NEEDS_INVESTIGATION", "REVIEW_COMPLETE"):
        return action
    raise ValueError("invalid source-review transition")


def event(batch, batch_pin, task_id, previous, action, at, reviewer, note):
    status = previous[-1]["resultingStatus"] if previous else "PENDING_HUMAN_REVIEW"
    prior_time = previous[-1]["recordedAt"] if previous else batch["currentRecordedAt"]
    if utc(at) <= utc(prior_time):
        raise ValueError("disposition time must be later than observation and preceding event")
    return {"schemaVersion": "1", "batchId": batch["batchId"], "batchSHA256": batch_pin,
            "taskId": task_id, "sequence": len(previous)+1,
            "previousSHA256": digest(canonical(previous[-1])) if previous else None,
            "action": action, "resultingStatus": next_status(status, action),
            "recordedAt": at, "reviewer": human_text(reviewer, 128),
            "note": human_text(note, 1024), "reviewerAuthentication": "NOT_ESTABLISHED",
            "scope": "SOURCE_CLAIM_REVIEW_ONLY", "trustStatus": "NOT_ESTABLISHED"}


def task_dir(root, batch, task_id, create=False):
    # IDs come from a replayed batch and exact task membership.
    parent = root / (batch["batchId"] + ".dispositions")
    path = parent / task_id
    for p in (parent, path):
        if create:
            p.mkdir(mode=0o700, exist_ok=True)
        try:
            private_root(p)
        except FileNotFoundError:
            if create:
                raise
            return None
    return path


def read_event(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_EVENT_BYTES:
        raise ValueError("invalid disposition event file")
    with path.open("rb") as handle:
        if not os.path.samestat(info, os.fstat(handle.fileno())):
            raise ValueError("disposition changed while opening")
        raw = handle.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError("disposition exceeds size limit")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if canonical(value) != raw:
        raise ValueError("noncanonical disposition event")
    return value


def history(path, batch, batch_pin, task_id, locked=False):
    if path is None:
        return []
    # Bounded enumeration of this one task only, never the global queue.
    with os.scandir(path) as entries:
        names = sorted(e.name for e in itertools.islice(entries, MAX_EVENTS+2))
    if ".lock" in names:
        if not locked:
            raise ValueError("task disposition stream is busy")
        names.remove(".lock")
    if len(names) > MAX_EVENTS or names != [f"{i:04d}.json" for i in range(1, len(names)+1)]:
        raise ValueError("unexpected or noncontiguous disposition history")
    result = []
    for name in names:
        value = read_event(path / name)
        expected = event(batch, batch_pin, task_id, result, value["action"],
                         value["recordedAt"], value["reviewer"], value["note"])
        if canonical(value) != canonical(expected):
            raise ValueError("disposition chain or task binding mismatch")
        result.append(value)
    return result


def head(events):
    return digest(canonical(events[-1])) if events else "EMPTY"


def report(batch, task_id, events):
    return {"batchId": batch["batchId"], "taskId": task_id, "eventCount": len(events),
            "headSHA256": head(events),
            "status": events[-1]["resultingStatus"] if events else "PENDING_HUMAN_REVIEW",
            "events": events, "scope": "SOURCE_CLAIM_REVIEW_ONLY",
            "liveProfileAccepted": False, "trustStatus": "NOT_ESTABLISHED"}


def inspect(root, batch, batch_pin, task_id):
    verify(root, batch, batch_pin)
    task_of(batch, task_id)
    return report(batch, task_id, history(task_dir(root, batch, task_id), batch, batch_pin, task_id))


def append(root, batch, batch_pin, task_id, expected_head, action, at, reviewer, note):
    verify(root, batch, batch_pin)
    task_of(batch, task_id)
    if expected_head != "EMPTY" and not HEX.fullmatch(expected_head):
        raise ValueError("explicit independent expected head or EMPTY required")
    if action not in ACTIONS:
        raise ValueError("unknown disposition action")
    utc(at)
    human_text(reviewer, 128)
    human_text(note, 1024)
    path = task_dir(root, batch, task_id, create=True)
    lock = path / ".lock"
    lock.mkdir(mode=0o700)
    try:
        events = history(path, batch, batch_pin, task_id, locked=True)
        if head(events) != expected_head:
            raise ValueError("disposition head mismatch; inspect current history")
        if len(events) >= MAX_EVENTS:
            raise ValueError("disposition history limit reached; preserve and review")
        value = event(batch, batch_pin, task_id, events, action, at, reviewer, note)
        data = canonical(value)
        if len(data) > MAX_EVENT_BYTES:
            raise ValueError("disposition event size limit")
        # Keep temporary files outside the task history. A no-replace link
        # is the commit point; existing event files are never edited.
        fd, tmp = tempfile.mkstemp(prefix=".disposition-pending-", dir=root)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(tmp, path / f"{value['sequence']:04d}.json")
        finally:
            os.unlink(tmp)
        return report(batch, task_id, events + [value])
    finally:
        lock.rmdir()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=("history", "record"))
    p.add_argument("previous", type=Path)
    p.add_argument("current", type=Path)
    p.add_argument("--previous-sha256", required=True)
    p.add_argument("--current-sha256", required=True)
    p.add_argument("--queue", type=Path, required=True)
    p.add_argument("--batch-sha256", required=True)
    p.add_argument("--task-id", required=True)
    p.add_argument("--expected-head")
    p.add_argument("--action", choices=ACTIONS)
    p.add_argument("--at")
    p.add_argument("--reviewer")
    p.add_argument("--note")
    args = p.parse_args()
    fields = (args.expected_head, args.action, args.at, args.reviewer, args.note)
    if (args.operation == "record" and not all(fields)) or (args.operation == "history" and any(v is not None for v in fields)):
        p.error("record requires all disposition fields; history accepts none")
    try:
        batch = prepare(read_observation(args.previous), args.previous_sha256,
                        read_observation(args.current), args.current_sha256)
        if args.operation == "record":
            r = append(args.queue, batch, args.batch_sha256, args.task_id, *fields)
        else:
            r = inspect(args.queue, batch, args.batch_sha256, args.task_id)
        print(json.dumps(r, ensure_ascii=True, indent=2))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print("SHECA disposition: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
