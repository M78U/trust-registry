"""Bounded local operational alerts. No delivery or trust authorization."""
import json
import os
import re
import stat
import tempfile

from sheca_source_adapter import digest, unique_object
from sheca_source_review_queue import canonical, private_root
from sheca_source_review_disposition import utc
from trust_maintainer_workspace import SOURCES

FILE = "maintenance-alerts.json"
MAX_BYTES = 65536
HEX = re.compile(r"[0-9a-f]{64}")
KINDS = ("SOURCE_BODY_CHANGED", "REPEATED_FETCH_FAILURE", "SOURCE_STATE_REVIEW",
         "WORKSPACE_CHECK_FAILED")
LOCAL_FAILURES = ("LOCAL_STATE_REVIEW_REQUIRED", "STORE_WRITE_FAILED", "CANCELLED", "STREAM_BUSY")
NORMAL = ("BASELINE_CAPTURED", "BODY_UNCHANGED", "BODY_CHANGED_REVIEW_REQUIRED",
          "NOT_DUE_UNDER_LOCAL_POLICY", "RETRY_COOLDOWN_ACTIVE", "FETCH_BUDGET_EXHAUSTED")


def empty():
    return {"schemaVersion": "1", "lastReceiptSHA256": None, "failureStreaks": {}, "alerts": {}}


def validate(state):
    if not isinstance(state, dict) or set(state) != set(empty()) or state["schemaVersion"] != "1":
        raise ValueError("invalid maintenance alert state")
    pin = state["lastReceiptSHA256"]
    if pin is not None and (not isinstance(pin, str) or not HEX.fullmatch(pin)):
        raise ValueError("invalid receipt digest")
    streaks = state["failureStreaks"]
    if not isinstance(streaks, dict) or any(k not in SOURCES or type(v) is not int or not 1 <= v <= 255 for k, v in streaks.items()):
        raise ValueError("invalid failure streaks")
    alerts = state["alerts"]
    if not isinstance(alerts, dict) or len(alerts) > 25:
        raise ValueError("invalid alert count")
    for key, a in alerts.items():
        if not isinstance(a, dict) or set(a) != {"sourceId", "kind", "firstAt", "lastAt", "occurrences", "receiptSHA256"}:
            raise ValueError("invalid alert fields")
        source, kind = a["sourceId"], a["kind"]
        if kind not in KINDS or (source != "workspace" if kind == KINDS[3] else source not in SOURCES) or key != source + ":" + kind:
            raise ValueError("invalid alert identity")
        if utc(a["lastAt"]) < utc(a["firstAt"]) or type(a["occurrences"]) is not int or not 1 <= a["occurrences"] <= 65535 or not HEX.fullmatch(a["receiptSHA256"]):
            raise ValueError("invalid alert metadata")


def load(root):
    private_root(root)
    path = root / FILE
    try:
        info = path.lstat()
    except FileNotFoundError:
        return empty()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= MAX_BYTES:
        raise ValueError("invalid private alert file")
    with path.open("rb") as f:
        if not os.path.samestat(info, os.fstat(f.fileno())):
            raise ValueError("alert file changed while opening")
        raw = f.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("alert file size limit")
    state = json.loads(raw, object_pairs_hook=unique_object)
    validate(state)
    if canonical(state) != raw:
        raise ValueError("noncanonical alert state")
    return state


def save(root, state):
    validate(state)
    raw = canonical(state)
    if len(raw) > MAX_BYTES:
        raise ValueError("alert file size limit")
    fd, temp = tempfile.mkstemp(prefix=".alerts-pending-", dir=root)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, root / FILE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def observe(root, receipt):
    """Called under the cooperating workspace lock, replay latest receipt only."""
    state = load(root)
    if receipt["status"] == "NO_SCHEDULED_CHECK_RECEIPT":
        return state
    pin = digest(canonical(receipt))
    if state["lastReceiptSHA256"] == pin:
        return state
    at = receipt["finishedAt"]
    utc(at)
    def add(source, kind):
        key = source + ":" + kind
        prior = state["alerts"].get(key)
        if prior and utc(at) < utc(prior["lastAt"]):
            raise ValueError("receipt time precedes pending alert")
        state["alerts"][key] = {"sourceId": source, "kind": kind,
                                "firstAt": prior["firstAt"] if prior else at, "lastAt": at,
                                "occurrences": min(65535, prior["occurrences"]+1) if prior else 1,
                                "receiptSHA256": pin}
    report = receipt.get("monitorReport")
    if receipt["status"] == "CHECK_FAILED":
        add("workspace", "WORKSPACE_CHECK_FAILED")
    elif receipt["status"] in ("CHECK_COMPLETED", "CHECK_INCOMPLETE"):
        if not isinstance(report, dict) or report.get("trustStatus") != "NOT_ESTABLISHED" or report.get("sourceAuthentication") != "NOT_ESTABLISHED":
            raise ValueError("unexpected scheduled monitor report")
        rows = report["rows"]
        if not isinstance(rows, list) or len(rows) > len(SOURCES):
            raise ValueError("unexpected source row count")
        seen = set()
        for row in rows:
            source, status = row["source"]["id"], row["status"]
            if source not in SOURCES or source in seen:
                raise ValueError("unexpected source row")
            seen.add(source)
            if status == "SOURCE_FETCH_FAILED":
                n = min(255, state["failureStreaks"].get(source, 0)+1)
                state["failureStreaks"][source] = n
                if n >= 2:
                    add(source, "REPEATED_FETCH_FAILURE")
            elif status in LOCAL_FAILURES:
                add(source, "SOURCE_STATE_REVIEW")
            elif status in NORMAL:
                if status in NORMAL[:3]:
                    state["failureStreaks"].pop(source, None)
                if status == "BODY_CHANGED_REVIEW_REQUIRED":
                    add(source, "SOURCE_BODY_CHANGED")
            else:
                raise ValueError("unknown source status; review monitor report")
    else:
        raise ValueError("unknown scheduled receipt status")
    state["lastReceiptSHA256"] = pin
    save(root, state)
    return state


def listing(state):
    return {"status": "LOCAL_PENDING_ALERTS", "stateSHA256": digest(canonical(state)),
            "pendingCount": len(state["alerts"]),
            "alerts": [{"alertId": k, **a} for k, a in sorted(state["alerts"].items())],
            "failureStreaks": state["failureStreaks"],
            "delivery": "LOCAL_ONLY", "trustStatus": "NOT_ESTABLISHED"}


def acknowledge(root, state, expected, alert_id):
    if not HEX.fullmatch(expected) or digest(canonical(state)) != expected:
        raise ValueError("alert state changed; inspect current alerts")
    if alert_id not in state["alerts"]:
        raise ValueError("unknown pending alert")
    del state["alerts"][alert_id]
    save(root, state)
    return listing(state)
