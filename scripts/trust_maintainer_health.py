"""Read-only, local maintainer health report; no network or scheduler claim."""
import datetime as dt
from pathlib import Path
import stat

from sheca_source_adapter import digest
from sheca_source_review_queue import canonical, private_root
import trust_maintainer_workspace as workspace
import trust_maintainer_schedule as schedule
import trust_maintainer_alerts as alerts
import trust_maintainer_webhook as webhook
import sheca_source_review_index as index

ERRORS = (ValueError, TypeError, KeyError, OSError, RecursionError, OverflowError)


def health(root, at, max_age_hours=36):
    if type(max_age_hours) is not int or not 1 <= max_age_hours <= 720:
        raise ValueError("maximum check age must be 1 to 720 whole hours")
    now = webhook.instant(at)
    private_root(root)
    checks = []

    def add(name, status, **fields):
        checks.append({"check": name, "status": status, **fields})

    def present(path):
        try:
            path.lstat()
            return True
        except FileNotFoundError:
            return False

    config_pin = None
    try:
        config = workspace.read_config(root)
        config_pin = digest(canonical(config))
        add("workspace", "OK")
        try:
            matched = workspace.binary_digest(Path(config["binary"])) == config["binarySHA256"]
            add("cliBinding", "OK" if matched else "REVIEW_REQUIRED")
        except ERRORS:
            add("cliBinding", "REVIEW_REQUIRED")
    except ERRORS:
        add("workspace", "REVIEW_REQUIRED")
        add("cliBinding", "NOT_CHECKED")

    # A lock is not proof of an active process or a stale lock.
    add("workspaceLock", "REVIEW_REQUIRED" if present(root / workspace.LOCK) else "NOT_PRESENT")
    receipt_pin = None
    try:
        r = schedule.last(root)
        if r["status"] == "NO_SCHEDULED_CHECK_RECEIPT":
            add("scheduledReceipt", "NOT_YET_RECORDED")
        else:
            started = webhook.instant(r["startedAt"])
            finished = webhook.instant(r["finishedAt"])
            if started > finished or finished > now:
                raise ValueError("invalid receipt chronology")
            if r["status"] not in ("CHECK_COMPLETED", "CHECK_INCOMPLETE", "CHECK_FAILED") or type(r["exitCode"]) is not int:
                raise ValueError("invalid receipt outcome")
            age = int((now - finished).total_seconds())
            receipt_pin = digest(canonical(r))
            reasons = []
            if (now - finished) > dt.timedelta(hours=max_age_hours):
                reasons.append("RECEIPT_TOO_OLD")
            if r["status"] != "CHECK_COMPLETED" or r["exitCode"] != 0:
                reasons.append("LAST_CHECK_NOT_SUCCESSFUL")
            if config_pin is None or r["configurationSHA256"] != config_pin:
                reasons.append("CURRENT_CONFIGURATION_NOT_CONFIRMED")
            add("scheduledReceipt", "REVIEW_REQUIRED" if reasons else "OK",
                ageSeconds=age, finishedAt=r["finishedAt"], reasons=reasons)
    except ERRORS:
        add("scheduledReceipt", "REVIEW_REQUIRED", reasons=["INVALID_OR_UNREADABLE_RECEIPT"])

    state = None
    try:
        state = alerts.load(root)
        reconciled = state["lastReceiptSHA256"] == receipt_pin
        add("alerts", "REVIEW_REQUIRED" if state["alerts"] or not reconciled else "OK",
            pendingCount=len(state["alerts"]), receiptReconciled=reconciled)
    except ERRORS:
        add("alerts", "REVIEW_REQUIRED")
    try:
        cache = index.listing(root, "open", 1, 0)
        add("reviewIndex", "REVIEW_REQUIRED" if cache["matching"] else "ADVISORY_ONLY",
            indexedBatches=cache["batchCount"], indexedOpenTasks=cache["matching"],
            freshness="NOT_RECHECKED", coverage="EXPLICITLY_REFRESHED_BATCHES_ONLY")
    except ERRORS:
        add("reviewIndex", "REVIEW_REQUIRED")
    try:
        cfg = webhook.configuration(root)
        if cfg is None:
            add("webhook", "DISABLED")
        else:
            delivery = webhook.load(root)
            outcome = delivery["lastOutcome"]
            attempt = delivery["lastAttemptAt"]
            problems = outcome in ("ATTEMPT_RESERVED", "FAILED_OR_UNCONFIRMED")
            if attempt is not None and webhook.instant(attempt) > now:
                problems = True
            unsent = None
            if state is not None:
                unsent = sum(delivery["delivered"].get(k) != a["firstAt"]
                             for k, a in state["alerts"].items())
                problems = problems or bool(unsent)
            add("webhook", "REVIEW_REQUIRED" if problems else "CONFIGURED_NOT_CONTACTED",
                lastOutcome=outcome, undeliveredPendingSlots=unsent)
    except ERRORS:
        add("webhook", "REVIEW_REQUIRED")

    needs_review = any(c["status"] in ("REVIEW_REQUIRED", "NOT_YET_RECORDED", "NOT_CHECKED") for c in checks)
    return {"schemaVersion": "1", "status": "OPERATOR_REVIEW_REQUIRED" if needs_review else "LOCAL_CHECKS_OK",
            "checkedAt": at, "maxReceiptAgeHours": max_age_hours, "checks": checks,
            "schedulerInstallation": "NOT_CHECKED", "externalConnectivity": "NOT_CHECKED",
            "snapshotAtomicity": "NOT_ESTABLISHED", "liveProfileAccepted": False,
            "trustStatus": "NOT_ESTABLISHED"}
