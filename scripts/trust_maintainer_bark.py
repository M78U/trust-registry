"""Optional fixed-endpoint Bark delivery for sanitized local alert summaries."""
import datetime as dt
import http.client
import json
import os
import re
import ssl
import stat
import tempfile

from sheca_source_adapter import unique_object
from sheca_source_review_queue import canonical, private_root
from sheca_source_review_disposition import utc
from trust_maintainer_alerts import KINDS
from trust_maintainer_workspace import SOURCES

KEY = "bark-device-key"
FILE = "bark-delivery.json"
MAX_BYTES = 16384
COOLDOWN = dt.timedelta(hours=6)
HOST = "api.day.app"
PATH = "/push"
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


def device_key(root):
    raw = private_read(root, KEY, 257)
    if raw is None:
        return None
    # Restrict to ordinary opaque Bark keys. Do not echo a credential on failure.
    if not re.fullmatch(rb"[A-Za-z0-9_-]{8,256}\n?", raw):
        raise ValueError("invalid Bark device key format")
    return raw.rstrip(b"\n").decode("ascii")


def empty():
    return {"schemaVersion": "1", "lastAttemptAt": None,
            "lastOutcome": "NONE", "delivered": {}}


def validate(state):
    if not isinstance(state, dict) or set(state) != set(empty()) or state["schemaVersion"] != "1":
        raise ValueError("invalid delivery state")
    if state["lastOutcome"] not in ("NONE", "ATTEMPT_RESERVED", "ACCEPTED_BY_RELAY", "FAILED_OR_UNCONFIRMED"):
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
    fd, temp = tempfile.mkstemp(prefix=".bark-delivery-pending-", dir=root)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, root / FILE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def send(key, body):
    # Fixed HTTPS endpoint, no shell, proxy, redirect or response/error echo.
    payload = json.dumps({"device_key": key, "title": "M78U Trust Registry",
                          "body": body, "group": "M78U Trust Registry"},
                         ensure_ascii=True).encode("ascii")
    conn = http.client.HTTPSConnection(HOST, port=443, timeout=10,
                                       context=ssl.create_default_context())
    try:
        conn.request("POST", PATH, body=payload,
                     headers={"Content-Type": "application/json; charset=utf-8",
                              "Accept": "application/json", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
            return False
        raw = response.read(4097)
        if len(raw) > 4096:
            return False
        answer = json.loads(raw, object_pairs_hook=unique_object)
        return isinstance(answer, dict) and type(answer.get("code")) is int and answer["code"] == 200
    except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError):
        return False
    finally:
        conn.close()


def notify(root, alert_state, now, transport=send):
    """Called under workspace lock. No acknowledgement or trust changes."""
    def result(status, count=0, attempted=False):
        return {"status": status, "alertCount": count, "requestAttempted": attempted,
                "trustStatus": "NOT_ESTABLISHED"}
    key = device_key(root)
    if key is None:
        return result("BARK_DISABLED_NO_KEY")
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
    # Only fixed source IDs and fixed descriptions, no paths, digests, URLs,
    # timestamps, credentials (except the required key), or raw source text.
    body = "Maintenance review required:\n" + "\n".join(
        a["sourceId"] + ": " + MESSAGES[a["kind"]] for _, a in pending)
    try:
        accepted = transport(key, body) is True
    except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError):
        accepted = False
    if accepted:
        state["delivered"].update({k: a["firstAt"] for k, a in pending})
        state["lastOutcome"] = "ACCEPTED_BY_RELAY"
    else:
        state["lastOutcome"] = "FAILED_OR_UNCONFIRMED"
    save(root, state)
    return result(state["lastOutcome"], len(pending), True)
