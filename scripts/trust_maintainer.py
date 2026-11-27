#!/usr/bin/env python3
"""Explicit local Trust Registry maintenance workflow. Never authorize trust."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

from sheca_source_adapter import digest, MAX_OBSERVATION
from sheca_source_acceptance import acceptance, DEFAULT_BASELINE, MAX_BASELINE, read_bounded
from sheca_source_diff import read_observation
from sheca_source_review_queue import prepare, canonical, persist, private_root
from sheca_source_review_disposition import append, inspect, ACTIONS, utc
from sheca_source_review_index import refresh, listing, STATES

ERRORS = (ValueError, TypeError, KeyError, OSError, RecursionError)
HEX = re.compile(r"[0-9a-f]{64}")


def plan(batch):
    return {"status": "REVIEW_BATCH_PREVIEW_ONLY", "batchSHA256": digest(canonical(batch)),
            "batch": batch, "liveProfileAccepted": False, "trustStatus": "NOT_ESTABLISHED"}


def pin_batch(batch, pin):
    if not HEX.fullmatch(pin) or digest(canonical(batch)) != pin:
        raise ValueError("independent expected batch digest mismatch")


def refresh_after_write(root, batch, pin, at, result):
    # The previous operation may already have committed. Never disguise
    # partial success as a failure that is safe to blindly retry.
    try:
        updated = refresh(root, batch, pin, at)
    except ERRORS as exc:
        return {"status": "WRITE_COMMITTED_INDEX_REFRESH_FAILED",
                "committed": result, "index": None, "detail": str(exc),
                "recovery": "REFRESH_ONLY_AFTER_INSPECTING_LOCAL_STATE",
                "liveProfileAccepted": False, "trustStatus": "NOT_ESTABLISHED"}, 1
    return {"status": "WRITE_COMMITTED_INDEX_REFRESHED", "committed": result,
            "index": updated, "liveProfileAccepted": False,
            "trustStatus": "NOT_ESTABLISHED"}, 0


def enqueue(root, batch, pin, at):
    pin_batch(batch, pin)
    if utc(at) < utc(batch["currentRecordedAt"]):
        raise ValueError("refresh precedes current observation")
    committed = persist(root, batch)
    return refresh_after_write(root, batch, pin, at, committed)


def record(root, batch, pin, task_id, expected_head, action, at, reviewer, note):
    pin_batch(batch, pin)
    committed = append(root, batch, pin, task_id, expected_head, action, at, reviewer, note)
    # The recorded event and refreshed index are separate commit boundaries.
    # A concurrent newer event or failed refresh must not cause an event retry.
    summary = {k: committed[k] for k in ("batchId", "taskId", "eventCount", "headSHA256", "status")}
    return refresh_after_write(root, batch, pin, at, summary)


def check(args):
    # The operator explicitly supplies a trusted locally built Go executable.
    # Do not search PATH, run a shell, accept arbitrary extra flags or interpret
    # any discovered URL as a command. Preserve the Go report and exit status.
    binary = args.binary
    if not binary.is_absolute() or not binary.is_file():
        raise ValueError("--binary must be an absolute path to the trusted CLI executable")
    private_root(args.store)
    if not 1 <= len(args.id) <= 8 or len(set(args.id)) != len(args.id) or not 1 <= args.max_fetches <= len(args.id):
        raise ValueError("explicit unique source IDs and bounded fetch budget required")
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", v) for v in args.id):
        raise ValueError("invalid source ID")
    # Go remains responsible for allowlist, duration, network and lock checks.
    command = [str(binary), "sources", "monitor-run", "--store", str(args.store),
               "--interval", args.interval, "--max-fetches", str(args.max_fetches)]
    for source in args.id:
        command.extend(("--id", source))
    return subprocess.run(command, check=False, timeout=360).returncode


def pair_args(p, queue=False, pin=False, at=False):
    p.add_argument("previous", type=Path)
    p.add_argument("current", type=Path)
    p.add_argument("--previous-sha256", required=True)
    p.add_argument("--current-sha256", required=True)
    if queue:
        p.add_argument("--queue", required=True, type=Path)
    if pin:
        p.add_argument("--batch-sha256", required=True)
    if at:
        p.add_argument("--at", required=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="operation", required=True)
    c = commands.add_parser("check", help="delegate one bounded online source run to trusted Go CLI")
    c.add_argument("--binary", required=True, type=Path)
    c.add_argument("--store", required=True, type=Path)
    c.add_argument("--interval", required=True)
    c.add_argument("--max-fetches", required=True, type=int)
    c.add_argument("--id", action="append", required=True)
    a = commands.add_parser("acceptance", help="cross-check one capture against selected research baseline")
    a.add_argument("observation", type=Path)
    a.add_argument("--sha256", required=True)
    pair_args(commands.add_parser("plan", help="preview review batch without writes"))
    pair_args(commands.add_parser("enqueue", help="persist explicitly pinned batch and refresh index"), True, True, True)
    pair_args(commands.add_parser("refresh", help="refresh existing pinned batch only"), True, True, True)
    h = commands.add_parser("history", help="verify selected task history")
    pair_args(h, True, True)
    h.add_argument("--task-id", required=True)
    r = commands.add_parser("record", help="append human disposition, then refresh advisory index")
    pair_args(r, True, True, True)
    r.add_argument("--task-id", required=True)
    r.add_argument("--expected-head", required=True)
    r.add_argument("--action", choices=ACTIONS, required=True)
    r.add_argument("--reviewer", required=True)
    r.add_argument("--note", required=True)
    s = commands.add_parser("status", help="read advisory index only")
    s.add_argument("--queue", required=True, type=Path)
    s.add_argument("--status", choices=("open", "all", *STATES), default="open")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--offset", type=int, default=0)
    return p


def execute(args):
    op = args.operation
    if op == "check":
        return None, check(args)
    if op == "status":
        return listing(args.queue, args.status, args.limit, args.offset), 0
    if op == "acceptance":
        return acceptance(read_bounded(args.observation, MAX_OBSERVATION), args.sha256,
                          read_bounded(DEFAULT_BASELINE, MAX_BASELINE)), 0
    batch = prepare(read_observation(args.previous), args.previous_sha256,
                    read_observation(args.current), args.current_sha256)
    if op == "plan":
        return plan(batch), 0
    if op == "enqueue":
        return enqueue(args.queue, batch, args.batch_sha256, args.at)
    if op == "refresh":
        return refresh(args.queue, batch, args.batch_sha256, args.at), 0
    if op == "history":
        return inspect(args.queue, batch, args.batch_sha256, args.task_id), 0
    if op == "record":
        return record(args.queue, batch, args.batch_sha256, args.task_id,
                      args.expected_head, args.action, args.at, args.reviewer, args.note)
    raise ValueError("unknown operation")


def main():
    args = parser().parse_args()
    try:
        result, code = execute(args)
        if result is not None:
            print(json.dumps(result, ensure_ascii=True, indent=2))
        return code
    except subprocess.TimeoutExpired:
        print("Maintainer: Go check timed out; inspect private state and locks before retry", file=sys.stderr)
        return 1
    except ERRORS as exc:
        print("Maintainer: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
