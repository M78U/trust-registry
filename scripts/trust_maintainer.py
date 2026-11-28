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
import trust_maintainer_workspace as workspace
import trust_maintainer_schedule as schedule
import trust_maintainer_alerts as alerts

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


def check_command(args):
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
    return command


def check(args):
    return subprocess.run(check_command(args), check=False, timeout=360).returncode


def pair_args(p, queue=False, pin=False, at=False):
    p.add_argument("previous", type=Path)
    p.add_argument("current", type=Path)
    p.add_argument("--previous-sha256", required=True)
    p.add_argument("--current-sha256", required=True)
    if queue:
        p.add_argument("--queue", type=Path)
    if pin:
        p.add_argument("--batch-sha256", required=True)
    if at:
        p.add_argument("--at", required=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path, help="explicit private workspace (before subcommand)")
    commands = p.add_subparsers(dest="operation", required=True)
    w = commands.add_parser("workspace-init", help="initialize a new private workspace")
    w.add_argument("--binary", required=True, type=Path)
    w.add_argument("--binary-sha256", required=True)
    w.add_argument("--interval-hours", required=True, type=int)
    w.add_argument("--max-fetches", required=True, type=int)
    w.add_argument("--id", action="append", required=True)
    commands.add_parser("workspace-info", help="read private workspace configuration")
    job = commands.add_parser("schedule-plist", help="render daily macOS LaunchAgent XML; never install")
    job.add_argument("--hour", required=True, type=int)
    job.add_argument("--minute", required=True, type=int)
    commands.add_parser("scheduled-check", help="one bounded check with latest private receipt")
    commands.add_parser("last-check", help="read latest scheduled check receipt")
    commands.add_parser("alerts", help="read local pending operational alerts")
    ack = commands.add_parser("alert-ack", help="acknowledge one alert without granting trust")
    ack.add_argument("--expected-state-sha256", required=True)
    ack.add_argument("--alert-id", required=True)
    u = commands.add_parser("workspace-update", help="replace configuration with explicit prior and binary pins")
    u.add_argument("--expected-config-sha256", required=True)
    u.add_argument("--binary", required=True, type=Path)
    u.add_argument("--binary-sha256", required=True)
    u.add_argument("--interval-hours", required=True, type=int)
    u.add_argument("--max-fetches", required=True, type=int)
    u.add_argument("--id", action="append", required=True)
    a = commands.add_parser("workspace-archive", help="replay one explicitly pinned old configuration")
    a.add_argument("--config-sha256", required=True)
    c = commands.add_parser("check", help="delegate one bounded online source run to trusted Go CLI")
    c.add_argument("--binary", type=Path)
    c.add_argument("--store", type=Path)
    c.add_argument("--interval")
    c.add_argument("--max-fetches", type=int)
    c.add_argument("--id", action="append")
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
    s.add_argument("--queue", type=Path)
    s.add_argument("--status", choices=("open", "all", *STATES), default="open")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--offset", type=int, default=0)
    return p


def execute(args):
    op = args.operation
    root = args.workspace
    if op in ("alerts", "alert-ack"):
        if root is None:
            raise ValueError("explicit --workspace path required before subcommand")
        with workspace.check_update_lock(root):
            state = alerts.observe(root, schedule.last(root))
            if op == "alert-ack":
                return alerts.acknowledge(root, state, args.expected_state_sha256, args.alert_id), 0
            return alerts.listing(state), 0
    if op in ("schedule-plist", "scheduled-check", "last-check"):
        if root is None:
            raise ValueError("explicit --workspace path required before subcommand")
        if op == "schedule-plist":
            return schedule.plist(root, args.hour, args.minute, Path(__file__).resolve(), Path(sys.executable).resolve()), 0
        if op == "scheduled-check":
            return schedule.scheduled_check(root, check_command)
        return schedule.last(root), 0
    if op in ("workspace-init", "workspace-info", "workspace-update", "workspace-archive"):
        if root is None:
            raise ValueError("explicit --workspace path required before subcommand")
        if op == "workspace-init":
            return workspace.initialize(root, args.binary, args.binary_sha256, args.interval_hours, args.max_fetches, args.id), 0
        if op == "workspace-update":
            return workspace.update(root, args.expected_config_sha256, args.binary, args.binary_sha256,
                                    args.interval_hours, args.max_fetches, args.id), 0
        if op == "workspace-archive":
            return workspace.archived(root, args.config_sha256), 0
        return workspace.describe(root, workspace.read_config(root)), 0
    if root is not None and op == "check":
        with workspace.check_update_lock(root):
            workspace.apply(root, args)
            return None, check(args)
    if root is not None:
        workspace.apply(root, args)
    if op == "check":
        if any(getattr(args, k) is None for k in ("binary", "store", "interval", "max_fetches", "id")):
            raise ValueError("explicit workspace or all direct check options required")
        return None, check(args)
    if op in ("enqueue", "refresh", "history", "record", "status") and args.queue is None:
        raise ValueError("explicit workspace or --queue required")
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
        if isinstance(result, bytes):
            sys.stdout.buffer.write(result)
        elif result is not None:
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
