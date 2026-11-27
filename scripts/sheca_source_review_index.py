#!/usr/bin/env python3
"""Bounded advisory index of explicitly refreshed source-review batches."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from sheca_source_adapter import digest, unique_object
from sheca_source_diff import read_observation
from sheca_source_review_queue import canonical, prepare, private_root, verify
from sheca_source_review_disposition import history, task_dir, head, utc

INDEX = "review-index.json"
MAX_INDEX_BYTES = 4 << 20
MAX_BATCHES = 64
MAX_BATCH_TASKS = 512
MAX_TASKS = 4096
HEX = re.compile(r"[0-9a-f]{64}")
SHA1 = re.compile(r"[0-9a-f]{40}")
STATES = ("PENDING_HUMAN_REVIEW", "NEEDS_INVESTIGATION", "REVIEW_COMPLETE")
KINDS = ("NEW_PUBLISHED_FINGERPRINT_CLAIM", "PUBLISHED_FINGERPRINT_NOT_OBSERVED",
         "AMBIGUOUS_FINGERPRINT_GROUP_CHANGED", "SINGLE_CLAIM_FIELDS_CHANGED",
         "AMBIGUOUS_PUBLISHED_SHA1_REVIEW", "EXACT_DUPLICATE_COUNT_REVIEW",
         "RAW_SOURCE_BODY_REVIEW")


def empty():
    return {"schemaVersion": "1", "batches": []}


def validate(index):
    if set(index) != {"schemaVersion", "batches"} or index["schemaVersion"] != "1" or not isinstance(index["batches"], list) or len(index["batches"]) > MAX_BATCHES:
        raise ValueError("invalid review index")
    previous = ""
    total = 0
    for b in index["batches"]:
        if set(b) != {"batchId", "batchSHA256", "sourceId", "previousSHA256", "currentSHA256",
                      "currentRecordedAt", "refreshedAt", "tasks"}:
            raise ValueError("invalid indexed batch fields")
        if any(not HEX.fullmatch(b[k]) for k in ("batchId", "batchSHA256", "previousSHA256", "currentSHA256")) or b["batchId"] <= previous or b["sourceId"] != "sheca-repository":
            raise ValueError("invalid indexed batch identity")
        identity = {"schemaVersion": "1", "sourceId": b["sourceId"], "adapter": "SHECA_TABLE_V1",
                    "previousSHA256": b["previousSHA256"], "currentSHA256": b["currentSHA256"]}
        if digest(canonical(identity)) != b["batchId"] or utc(b["refreshedAt"]) < utc(b["currentRecordedAt"]):
            raise ValueError("inconsistent indexed batch identity or time")
        previous = b["batchId"]
        if not isinstance(b["tasks"], list) or len(b["tasks"]) > MAX_BATCH_TASKS:
            raise ValueError("indexed batch task limit")
        total += len(b["tasks"])
        prior_task = ""
        for t in b["tasks"]:
            if set(t) != {"taskId", "kind", "publishedSHA1", "status", "headSHA256", "eventCount"}:
                raise ValueError("invalid indexed task fields")
            if not HEX.fullmatch(t["taskId"]) or t["taskId"] <= prior_task or t["kind"] not in KINDS or t["status"] not in STATES:
                raise ValueError("invalid indexed task")
            claim = t["publishedSHA1"]
            if t["kind"] in ("EXACT_DUPLICATE_COUNT_REVIEW", "RAW_SOURCE_BODY_REVIEW"):
                if claim is not None:
                    raise ValueError("source-wide task must not have a fingerprint")
            elif not isinstance(claim, str) or not SHA1.fullmatch(claim):
                raise ValueError("invalid indexed fingerprint claim")
            subject = {"batchId": b["batchId"], "kind": t["kind"], "publishedSHA1": claim}
            if digest(canonical(subject)) != t["taskId"]:
                raise ValueError("indexed task identity mismatch")
            if type(t["eventCount"]) is not int or not 0 <= t["eventCount"] <= 32:
                raise ValueError("invalid indexed event count")
            if t["eventCount"] == 0:
                if t["headSHA256"] != "EMPTY" or t["status"] != STATES[0]:
                    raise ValueError("inconsistent empty task history")
            elif not HEX.fullmatch(t["headSHA256"]):
                raise ValueError("invalid indexed head")
            prior_task = t["taskId"]
    if total > MAX_TASKS:
        raise ValueError("review index total task limit")


def load(root):
    private_root(root)
    path = root / INDEX
    try:
        info = path.lstat()
    except FileNotFoundError:
        return empty()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_INDEX_BYTES:
        raise ValueError("invalid review index file")
    with path.open("rb") as f:
        if not os.path.samestat(info, os.fstat(f.fileno())):
            raise ValueError("review index changed while opening")
        data = f.read(MAX_INDEX_BYTES + 1)
    if len(data) > MAX_INDEX_BYTES:
        raise ValueError("review index size limit")
    index = json.loads(data, object_pairs_hook=unique_object)
    validate(index)
    if canonical(index) != data:
        raise ValueError("noncanonical review index")
    return index


def save(root, index):
    validate(index)
    data = canonical(index)
    if len(data) > MAX_INDEX_BYTES:
        raise ValueError("review index size limit")
    fd, tmp = tempfile.mkstemp(prefix=".review-index-pending-", dir=root)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, root / INDEX)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return digest(data)


def refresh(root, batch, batch_pin, at):
    verify(root, batch, batch_pin)
    if utc(at) < utc(batch["currentRecordedAt"]):
        raise ValueError("refresh precedes current observation")
    if len(batch["tasks"]) > MAX_BATCH_TASKS:
        raise ValueError("batch too large for advisory index")
    lock = root / ".review-index.lock"
    lock.mkdir(mode=0o700)
    try:
        index = load(root)
        old = next((b for b in index["batches"] if b["batchId"] == batch["batchId"]), None)
        if old:
            if old["batchSHA256"] != batch_pin or utc(at) < utc(old["refreshedAt"]):
                raise ValueError("indexed batch pin or refresh time conflict")
        elif len(index["batches"]) >= MAX_BATCHES:
            raise ValueError("review index batch capacity reached")
        if sum(len(b["tasks"]) for b in index["batches"] if b["batchId"] != batch["batchId"]) + len(batch["tasks"]) > MAX_TASKS:
            raise ValueError("review index task capacity reached")
        tasks = []
        old_tasks = {t["taskId"]: t for t in old["tasks"]} if old else {}
        if old and set(old_tasks) != {t["taskId"] for t in batch["tasks"]}:
            raise ValueError("indexed task membership mismatch")
        for task in batch["tasks"]:
            task_id = task["taskId"]
            events = history(task_dir(root, batch, task_id), batch, batch_pin, task_id)
            if events and utc(at) < utc(events[-1]["recordedAt"]):
                raise ValueError("refresh precedes latest disposition")
            # Detect loss or rewrite of previously indexed history where possible.
            # This remains a local advisory cache, not authenticated rollback protection.
            prior = old_tasks.get(task_id)
            if prior and prior["eventCount"]:
                n = prior["eventCount"]
                if len(events) < n or digest(canonical(events[n-1])) != prior["headSHA256"]:
                    raise ValueError("previously indexed disposition head no longer present")
            tasks.append({"taskId": task_id, "kind": task["kind"],
                          "publishedSHA1": task["publishedSHA1"],
                          "status": events[-1]["resultingStatus"] if events else STATES[0],
                          "headSHA256": head(events), "eventCount": len(events)})
        summary = {"batchId": batch["batchId"], "batchSHA256": batch_pin,
                   "sourceId": batch["sourceId"], "previousSHA256": batch["previousSHA256"],
                   "currentSHA256": batch["currentSHA256"], "currentRecordedAt": batch["currentRecordedAt"],
                   "refreshedAt": at, "tasks": sorted(tasks, key=lambda t: t["taskId"])}
        index["batches"] = sorted([b for b in index["batches"] if b["batchId"] != batch["batchId"]] + [summary],
                                  key=lambda b: b["batchId"])
        pin = save(root, index)
        return {"status": "ADVISORY_BATCH_REFRESHED", "batchId": batch["batchId"],
                "indexSHA256": pin, "taskCount": len(tasks), "refreshedAt": at,
                "trustStatus": "NOT_ESTABLISHED"}
    finally:
        lock.rmdir()


def listing(root, status="open", limit=100, offset=0):
    if status not in ("open", "all", *STATES) or type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= MAX_TASKS:
        raise ValueError("invalid status or page bounds")
    index = load(root)
    counts = dict.fromkeys(STATES, 0)
    rows = []
    for b in index["batches"]:
        for t in b["tasks"]:
            counts[t["status"]] += 1
            if status == "all" or status == t["status"] or status == "open" and t["status"] != STATES[2]:
                rows.append({"batchId": b["batchId"], "batchSHA256": b["batchSHA256"],
                             "sourceId": b["sourceId"], "refreshedAt": b["refreshedAt"], **t})
    return {"status": "ADVISORY_INDEX_ONLY", "coverage": "EXPLICITLY_REFRESHED_BATCHES_ONLY",
            "freshness": "NOT_RECHECKED", "indexSHA256": digest(canonical(index)),
            "batchCount": len(index["batches"]), "counts": counts, "matching": len(rows),
            "offset": offset, "limit": limit,
            "nextOffset": offset+limit if offset+limit < len(rows) else None,
            "tasks": rows[offset:offset+limit], "liveProfileAccepted": False,
            "trustStatus": "NOT_ESTABLISHED"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)
    r = sub.add_parser("refresh")
    r.add_argument("previous", type=Path)
    r.add_argument("current", type=Path)
    r.add_argument("--previous-sha256", required=True)
    r.add_argument("--current-sha256", required=True)
    r.add_argument("--batch-sha256", required=True)
    r.add_argument("--queue", type=Path, required=True)
    r.add_argument("--at", required=True)
    q = sub.add_parser("list")
    q.add_argument("--queue", type=Path, required=True)
    q.add_argument("--status", choices=("open", "all", *STATES), default="open")
    q.add_argument("--limit", type=int, default=100)
    q.add_argument("--offset", type=int, default=0)
    args = p.parse_args()
    try:
        if args.operation == "refresh":
            batch = prepare(read_observation(args.previous), args.previous_sha256,
                            read_observation(args.current), args.current_sha256)
            result = refresh(args.queue, batch, args.batch_sha256, args.at)
        else:
            result = listing(args.queue, args.status, args.limit, args.offset)
        print(json.dumps(result, ensure_ascii=True, indent=2))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print("Source review index: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
