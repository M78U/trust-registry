"""Optional product-neutral HTTPS webhook delivery for local alert summaries."""
import datetime as dt
import http.client
import json
import os
import re
import ssl
import stat
import tempfile
from urllib.parse import urlsplit

from sheca_source_adapter import unique_object
from sheca_source_review_queue import canonical, private_root
from sheca_source_review_disposition import utc
from trust_maintainer_alerts import KINDS
from trust_maintainer_workspace import SOURCES

CONFIG = "notification-webhook.json"
FILE = "webhook-delivery.json"
MAX_BYTES = 16384
COOLDOWN = dt.timedelta(hours=6)
MESSAGES = {
    "SOURCE_BODY_CHANGED": "source content changed",
    "REPEATED_FETCH_FAILURE": "repeated fetch failures",
    "SOURCE_STATE_REVIEW": "local source state requires review",
    "WORKSPACE_CHECK_FAILED": "workspace check failed",
}


def instant(value):
    utc(value)
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def private_read(root, name, limit):
    private_root(root)
    path = root / name
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
            or info.st_uid != os.getuid() or not 0 < info.st_size <= limit):
        raise ValueError("invalid private notification file")
    with path.open("rb") as f:
        if not os.path.samestat(info, os.fstat(f.fileno())):
            raise ValueError("notification file changed while opening")
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("notification file size limit")
    return raw


def configuration(root):
    raw = private_read(root, CONFIG, MAX_BYTES)
    if raw is None:
        return None
    try:
        config = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(config, dict) or set(config) not in ({"url"}, {"url", "bearerToken"}):
            raise ValueError()
        url = config["url"]
        if not isinstance(url, str) or not 0 < len(url) <= 4096 or not all(33 <= ord(c) <= 126 for c in url):
            raise ValueError()
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or "#" in url or "\\" in url:
            raise ValueError()
        if not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname) or not parsed.hostname.strip("."):
            raise ValueError()
        port = parsed.port or 443
        if not 1 <= port <= 65535 or parsed.port == 0:
            raise ValueError()
        token = config.get("bearerToken")
        if "bearerToken" in config and (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/\-=]{1,4096}", token)):
            raise ValueError()
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        return {"host": parsed.hostname, "port": port, "target": target, "token": token}
    except (ValueError, TypeError, KeyError, RecursionError):
        # The URL itself can contain credentials. Never include it in errors.
        raise ValueError("invalid private webhook configuration") from None


def empty():
    return {"schemaVersion": "1", "lastAttemptAt": None,
            "lastOutcome": "NONE", "delivered": {}}


def validate(state):
    if not isinstance(state, dict) or set(state) != set(empty()) or state["schemaVersion"] != "1":
        raise ValueError("invalid delivery state")
    if state["lastOutcome"] not in ("NONE", "ATTEMPT_RESERVED", "ACCEPTED_BY_ENDPOINT", "FAILED_OR_UNCONFIRMED"):
        raise ValueError("invalid delivery outcome")
    if (state["lastAttemptAt"] is None) != (state["lastOutcome"] == "NONE"):
        raise ValueError("inconsistent attempt state")
    if state["lastAttemptAt"] is not None:
        utc(state["lastAttemptAt"])
    slots = state["delivered"]
    if not isinstance(slots, dict) or len(slots) > 25:
        raise ValueError("invalid delivered slots")
    for key, first in slots.items():
        source, sep, kind = key.partition(":")
        if not sep or kind not in KINDS or (source != "workspace" if kind == KINDS[3] else source not in SOURCES):
            raise ValueError("invalid delivered slot")
        utc(first)


def load(root):
    raw = private_read(root, FILE, MAX_BYTES)
    if raw is None:
        return empty()
    state = json.loads(raw, object_pairs_hook=unique_object)
    validate(state)
    if canonical(state) != raw:
        raise ValueError("noncanonical delivery state")
    return state


def save(root, state):
    validate(state)
    raw = canonical(state)
    if len(raw) > MAX_BYTES:
        raise ValueError("delivery state size limit")
    fd, temp = tempfile.mkstemp(prefix=".webhook-delivery-pending-", dir=root)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, root / FILE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def send(config, payload):
    # Explicit operator endpoint only. No redirects, proxy or response/error echo.
    headers = {"Content-Type": "application/json; charset=utf-8",
               "Accept": "application/json", "Accept-Encoding": "identity"}
    if config["token"] is not None:
        headers["Authorization"] = "Bearer " + config["token"]
    conn = None
    try:
        conn = http.client.HTTPSConnection(config["host"], port=config["port"], timeout=10,
                                           context=ssl.create_default_context())
        conn.request("POST", config["target"], body=canonical(payload), headers=headers)
        response = conn.getresponse()
        return 200 <= response.status < 300
    except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError):
        return False
    finally:
        if conn is not None:
            conn.close()


def notify(root, alert_state, now, transport=send):
    """Called under workspace lock. No acknowledgement or trust changes."""
    def result(status, count=0, attempted=False):
        return {"status": status, "alertCount": count, "requestAttempted": attempted,
                "trustStatus": "NOT_ESTABLISHED"}
    config = configuration(root)
    if config is None:
        return result("WEBHOOK_DISABLED_NO_CONFIG")
    state = load(root)
    at = instant(now)
    active = alert_state["alerts"]
    delivered = {k: v for k, v in state["delivered"].items()
                 if k in active and active[k]["firstAt"] == v}
    pending = [(k, a) for k, a in sorted(active.items()) if k not in delivered]
    if not pending:
        if delivered != state["delivered"]:
            state["delivered"] = delivered
            save(root, state)
        return result("NO_NEW_ALERTS")
    if state["lastAttemptAt"] is not None:
        prior = instant(state["lastAttemptAt"])
        if at < prior:
            raise ValueError("notification clock precedes last attempt")
        if at - prior < COOLDOWN:
            return result("DELIVERY_COOLDOWN_ACTIVE", len(pending))
    # Persist reservation before request, including after process interruption.
    state["delivered"] = delivered
    state["lastAttemptAt"] = now
    state["lastOutcome"] = "ATTEMPT_RESERVED"
    save(root, state)
    # Fixed schema and allowlisted source/kind data only.
    payload = {"schemaVersion": "1", "event": "trust-registry.maintenance.alerts",
               "title": "M78U Trust Registry", "alertCount": len(pending),
               "alerts": [{"sourceId": a["sourceId"], "kind": a["kind"],
                           "message": MESSAGES[a["kind"]]} for _, a in pending]}
    try:
        accepted = transport(config, payload) is True
    except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError):
        accepted = False
    if accepted:
        state["delivered"].update({k: a["firstAt"] for k, a in pending})
        state["lastOutcome"] = "ACCEPTED_BY_ENDPOINT"
    else:
        state["lastOutcome"] = "FAILED_OR_UNCONFIRMED"
    save(root, state)
    return result(state["lastOutcome"], len(pending), True)
