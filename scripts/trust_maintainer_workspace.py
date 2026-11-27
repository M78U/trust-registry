"""Private explicit maintainer workspace configuration (no scheduler)."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from sheca_source_adapter import digest, unique_object
from sheca_source_review_queue import canonical, private_root

CONFIG = "workspace.json"
HISTORY = "configuration-history"
LOCK = ".workspace-check-update.lock"
MAX_CONFIG_BYTES = 16384
MAX_BINARY_BYTES = 128 << 20
SOURCES = ("bjca-downloads", "bjca-root-directory", "cfca-repository",
           "gdca-repository", "satl-list", "satl-strategy",
           "sheca-auxiliary", "sheca-repository")
HEX = re.compile(r"[0-9a-f]{64}")


def binary_digest(path):
    if not path.is_absolute():
        raise ValueError("absolute trusted CLI path required")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
            or info.st_mode & 0o022 or not 0 < info.st_size <= MAX_BINARY_BYTES):
        raise ValueError("regular executable CLI (not symlink or group/world writable) required")
    h = hashlib.sha256()
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not os.path.samestat(info, opened):
            raise ValueError("CLI changed while opening")
        remaining = MAX_BINARY_BYTES + 1
        while remaining:
            chunk = handle.read(min(1 << 20, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
        end = os.fstat(handle.fileno())
    if not remaining or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (end.st_size, end.st_mtime_ns, end.st_ctime_ns):
        raise ValueError("CLI size limit or concurrent change")
    return h.hexdigest()


def validate(config):
    if not isinstance(config, dict) or set(config) != {"schemaVersion", "binary", "binarySHA256", "intervalHours", "maxFetches", "sourceIds"} or config["schemaVersion"] != "1":
        raise ValueError("invalid workspace configuration")
    if (not isinstance(config["binary"], str) or not 0 < len(config["binary"]) <= 4096
            or not all(c.isprintable() for c in config["binary"])
            or not Path(config["binary"]).is_absolute() or not HEX.fullmatch(config["binarySHA256"])):
        raise ValueError("invalid workspace binary binding")
    hours = config["intervalHours"]
    ids = config["sourceIds"]
    budget = config["maxFetches"]
    if type(hours) is not int or not 1 <= hours <= 720:
        raise ValueError("interval hours must be 1 to 720")
    if not isinstance(ids, list) or not 1 <= len(ids) <= len(SOURCES) or any(i not in SOURCES for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("explicit unique allowlisted source IDs required")
    if type(budget) is not int or not 1 <= budget <= len(ids):
        raise ValueError("invalid workspace request budget")


def read_config_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= MAX_CONFIG_BYTES:
        raise ValueError("invalid private workspace config file")
    with path.open("rb") as f:
        if not os.path.samestat(info, os.fstat(f.fileno())):
            raise ValueError("workspace config changed while opening")
        raw = f.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("workspace config size limit")
    config = json.loads(raw, object_pairs_hook=unique_object)
    validate(config)
    if canonical(config) != raw:
        raise ValueError("noncanonical workspace config")
    return config


def read_config(root):
    private_root(root)
    config = read_config_file(root / CONFIG)
    private_root(root / "observations")
    private_root(root / "review-queue")
    return config


def commit_config(path, config, replace=False):
    validate(config)
    data = canonical(config)
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError("workspace config size limit")
    fd, temp = tempfile.mkstemp(prefix=".workspace-pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_config(root, config):
    commit_config(root / CONFIG, config)


@contextmanager
def check_update_lock(root):
    """Serialize cooperating workspace checks and configuration changes."""
    private_root(root)
    lock = root / LOCK
    lock.mkdir(mode=0o700)
    try:
        yield
    finally:
        lock.rmdir()


def configuration(binary, binary_pin, hours, budget, ids):
    config = {"schemaVersion": "1", "binary": str(binary), "binarySHA256": binary_pin,
              "intervalHours": hours, "maxFetches": budget, "sourceIds": list(ids)}
    validate(config)
    if binary_digest(binary) != binary_pin:
        raise ValueError("CLI digest mismatch")
    return config


def archive_configuration(root, config):
    archive = root / HISTORY
    archive.mkdir(mode=0o700, exist_ok=True)
    private_root(archive)
    pin = digest(canonical(config))
    path = archive / (pin + ".json")
    try:
        commit_config(path, config)
    except FileExistsError:
        if canonical(read_config_file(path)) != canonical(config):
            raise ValueError("historical configuration conflicts; preserve and investigate")
    return pin


def update(root, expected, binary, binary_pin, hours, budget, ids):
    if not HEX.fullmatch(expected):
        raise ValueError("explicit expected current configuration SHA-256 required")
    # Validate all proposed settings and binary before any configuration write.
    with check_update_lock(root):
        old = read_config(root)
        old_pin = digest(canonical(old))
        if expected != old_pin:
            raise ValueError("current configuration digest differs; inspect before update")
        new = configuration(binary, binary_pin, hours, budget, ids)
        if canonical(old) == canonical(new):
            return describe(root, old, "WORKSPACE_CONFIGURATION_UNCHANGED")
        archive_configuration(root, old)
        commit_config(root / CONFIG, new, replace=True)
        result = describe(root, new, "WORKSPACE_CONFIGURATION_UPDATED")
        result["previousConfigurationSHA256"] = old_pin
        result["previousConfigurationArchived"] = True
        result["binaryVerification"] = "MATCHED_AT_UPDATE_TIME"
        return result


def archived(root, pin):
    if not HEX.fullmatch(pin):
        raise ValueError("explicit historical configuration SHA-256 required")
    private_root(root)
    directory = root / HISTORY
    private_root(directory)
    config = read_config_file(directory / (pin + ".json"))
    if digest(canonical(config)) != pin:
        raise ValueError("historical configuration digest mismatch")
    return {"status": "HISTORICAL_CONFIGURATION_REPLAYED", "configuration": config,
            "configurationSHA256": pin, "binaryVerification": "NOT_RECHECKED_AT_INFO_TIME",
            "trustStatus": "NOT_ESTABLISHED"}



def initialize(root, binary, binary_pin, hours, budget, ids):
    config = configuration(binary, binary_pin, hours, budget, ids)
    # No adoption or overwrite of an existing directory, including symlinks.
    # If initialization is interrupted, leave partial state for inspection.
    root.mkdir(mode=0o700)
    (root / "observations").mkdir(mode=0o700)
    (root / "review-queue").mkdir(mode=0o700)
    write_config(root, config)
    return describe(root, config, "WORKSPACE_CREATED")


def describe(root, config, status="WORKSPACE_CONFIG_READ"):
    return {"status": status, "workspace": str(root), "configuration": config,
            "configurationSHA256": digest(canonical(config)),
            "observationStore": str(root / "observations"),
            "reviewQueue": str(root / "review-queue"),
            "binaryVerification": "NOT_RECHECKED_AT_INFO_TIME",
            "schedulerEnabled": False, "liveProfileAccepted": False,
            "trustStatus": "NOT_ESTABLISHED"}


def apply(root, args):
    config = read_config(root)
    if args.operation == "check":
        if any(getattr(args, k) is not None for k in ("binary", "store", "interval", "max_fetches", "id")):
            raise ValueError("workspace check does not accept direct configuration overrides")
        args.binary = Path(config["binary"])
        if binary_digest(args.binary) != config["binarySHA256"]:
            raise ValueError("configured CLI digest changed; review new binary before explicit rebind")
        args.store = root / "observations"
        args.interval = str(config["intervalHours"]) + "h"
        args.max_fetches = config["maxFetches"]
        args.id = config["sourceIds"]
    elif args.operation in ("enqueue", "refresh", "history", "record", "status"):
        if args.queue is not None:
            raise ValueError("workspace queue does not accept a direct path override")
        args.queue = root / "review-queue"
    else:
        raise ValueError("workspace not needed for this operation")
    return args
