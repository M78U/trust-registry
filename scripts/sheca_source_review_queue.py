#!/usr/bin/env python3
"""Prepare and replay private SHECA maintenance review batches; never approve trust."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from sheca_source_adapter import digest
from sheca_source_diff import compare, read_observation

MAX_BATCH_BYTES = 8 << 20


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def prepare(previous, previous_pin, current, current_pin):
    diff = compare(previous, previous_pin, current, current_pin)
    identity = {"sourceId": diff["sourceId"], "adapter": diff["adapter"],
                "previousSHA256": previous_pin, "currentSHA256": current_pin}
    batch_id = digest(canonical({"schemaVersion": "1", **identity}))
    tasks = []

    def add(kind, claim=None, fields=()):
        subject = {"batchId": batch_id, "kind": kind, "publishedSHA1": claim}
        tasks.append({"taskId": digest(canonical(subject)), "kind": kind,
                      "publishedSHA1": claim, "changedFields": list(fields),
                      "status": "PENDING_HUMAN_REVIEW",
                      "scope": "SOURCE_CLAIM_REVIEW_ONLY"})

    changed = set()
    for change in diff["changes"]:
        sha = change["publishedSHA1"]
        changed.add(sha)
        add(change["kind"], sha, change["changedFields"])
        if change["ambiguous"] and change["kind"] != "AMBIGUOUS_FINGERPRINT_GROUP_CHANGED":
            add("AMBIGUOUS_PUBLISHED_SHA1_REVIEW", sha)
    for sha in diff["ambiguousPublishedSHA1"]:
        if sha not in changed:
            add("AMBIGUOUS_PUBLISHED_SHA1_REVIEW", sha)
    if diff["exactDuplicateCountChanged"]:
        add("EXACT_DUPLICATE_COUNT_REVIEW")
    # Any body change may contain material not represented by the parser,
    # even if the projected certificate rows match. No suppression of it.
    if diff["bodyChanged"]:
        add("RAW_SOURCE_BODY_REVIEW")
    tasks.sort(key=lambda t: t["taskId"])
    return {"schemaVersion": "1", "batchId": batch_id, **identity,
            "previousRecordedAt": diff["previous"]["recordedAt"],
            "currentRecordedAt": diff["current"]["recordedAt"],
            "mode": diff["current"]["mode"],
            "diffSHA256": digest(canonical(diff)), "diffStatus": diff["status"],
            "tasks": tasks, "taskCount": len(tasks),
            "status": "REVIEW_REQUIRED" if tasks else "NO_TASKS_FROM_THIS_COMPARISON",
            "liveProfileAccepted": False, "sourceAuthentication": "NOT_ESTABLISHED",
            "certificateIdentity": "NOT_ESTABLISHED", "trustStatus": "NOT_ESTABLISHED"}


def private_root(root):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("existing private queue directory (0700) required")


def read_batch(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BATCH_BYTES:
        raise ValueError("invalid queue batch file")
    with path.open("rb") as f:
        opened = os.fstat(f.fileno())
        if not os.path.samestat(info, opened):
            raise ValueError("queue batch changed while opening")
        data = f.read(MAX_BATCH_BYTES + 1)
    if len(data) > MAX_BATCH_BYTES:
        raise ValueError("queue batch size limit")
    return data


def persist(root, batch):
    private_root(root)
    data = canonical(batch)
    if len(data) > MAX_BATCH_BYTES:
        raise ValueError("queue batch size limit")
    # Name derived from the exact observation pair, not caller input.
    path = root / (batch["batchId"] + ".json")
    status = "BATCH_CREATED"
    fd, tmp = tempfile.mkstemp(prefix=".batch-pending-", dir=root)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            if read_batch(path) != data:
                raise ValueError("existing batch differs; preserve it and review")
            status = "EXACT_BATCH_REUSED"
    finally:
        os.unlink(tmp)
    return receipt(batch, data, status)


def receipt(batch, data, status):
    return {"status": status, "batchId": batch["batchId"],
            "batchSHA256": digest(data), "taskCount": batch["taskCount"],
            "reviewStatus": batch["status"],
            "trustStatus": "NOT_ESTABLISHED", "liveProfileAccepted": False}


def verify(root, batch, pin):
    private_root(root)
    data = read_batch(root / (batch["batchId"] + ".json"))
    if digest(data) != pin or data != canonical(batch):
        raise ValueError("independent batch pin or exact replay mismatch")
    return receipt(batch, data, "PINNED_BATCH_REPLAYED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--previous-sha256", required=True)
    parser.add_argument("--current-sha256", required=True)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--batch-sha256")
    args = parser.parse_args()
    if (args.action == "verify") != bool(args.batch_sha256):
        parser.error("--batch-sha256 is required only for verify")
    try:
        batch = prepare(read_observation(args.previous), args.previous_sha256,
                        read_observation(args.current), args.current_sha256)
        if args.action == "prepare":
            result = persist(args.queue, batch)
        else:
            result = verify(args.queue, batch, args.batch_sha256)
        print(json.dumps(result, ensure_ascii=True, indent=2))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print("SHECA review queue: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
