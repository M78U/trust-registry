#!/usr/bin/env python3
"""Compare two independently pinned SHECA observations. Research only."""
import argparse
import json
from pathlib import Path
import sys

from sheca_source_adapter import MAX_OBSERVATION, project

FIELDS = ("section", "label", "publishedValidUntil", "linkText", "observedHrefs")


def time_key(value):
    # project validates UTC RFC3339. Preserve all nine possible fractional
    # digits, rather than truncating nanoseconds through Python datetime.
    whole, _, fraction = value[:-1].partition(".")
    return whole, fraction.ljust(9, "0")


def groups(rows):
    result = {}
    for row in rows:
        result.setdefault(row["publishedSHA1"], []).append(row)
    return result


def compare(previous, previous_pin, current, current_pin):
    # Reproject exact observations. Never accept a caller-edited projection
    # or treat parsing failure as an empty catalog.
    a, b = project(previous, previous_pin), project(current, current_pin)
    if a["mode"] != b["mode"] or time_key(b["recordedAt"]) <= time_key(a["recordedAt"]):
        raise ValueError("same observation mode and strictly increasing UTC time required")
    before, after = groups(a["rows"]), groups(b["rows"])
    changes = []
    ambiguous = []
    counts = {"newFingerprintClaims": 0, "missingFingerprintClaims": 0,
              "changedFingerprintGroups": 0, "unchangedFingerprintGroups": 0,
              "ambiguousFingerprintGroups": 0}
    for sha in sorted(before.keys() | after.keys()):
        old, new = before.get(sha, []), after.get(sha, [])
        multi = len(old) > 1 or len(new) > 1
        if multi:
            ambiguous.append(sha)
            counts["ambiguousFingerprintGroups"] += 1
        if old == new:
            counts["unchangedFingerprintGroups"] += 1
            continue
        fields = []
        if not old:
            kind = "NEW_PUBLISHED_FINGERPRINT_CLAIM"
            counts["newFingerprintClaims"] += 1
        elif not new:
            kind = "PUBLISHED_FINGERPRINT_NOT_OBSERVED"
            counts["missingFingerprintClaims"] += 1
        else:
            counts["changedFingerprintGroups"] += 1
            if multi:
                kind = "AMBIGUOUS_FINGERPRINT_GROUP_CHANGED"
            else:
                kind = "SINGLE_CLAIM_FIELDS_CHANGED"
                fields = [key for key in FIELDS if old[0][key] != new[0][key]]
        changes.append({"publishedSHA1": sha, "kind": kind,
                        "ambiguous": multi, "changedFields": fields,
                        "previousRows": old, "currentRows": new})
    duplicate_change = a["exactDuplicateRows"] != b["exactDuplicateRows"]
    body_changed = a["bodySHA256"] != b["bodySHA256"]
    status = "BODY_AND_PROJECTED_ROWS_UNCHANGED"
    if changes:
        status = "PROJECTED_CLAIMS_CHANGED_REVIEW_REQUIRED"
    elif duplicate_change:
        status = "EXACT_DUPLICATE_COUNT_CHANGED_REVIEW_REQUIRED"
    elif body_changed:
        status = "BODY_CHANGED_PROJECTED_ROWS_UNCHANGED"
    # An unchanged projection does not prove completeness or source freshness.
    # Ambiguity in either observation is always a review signal.
    review = bool(changes or duplicate_change or ambiguous)
    def metadata(p):
        return {k: p[k] for k in ("observationSHA256", "bodySHA256", "recordedAt", "mode", "exactDuplicateRows")}
    return {"schemaVersion": "1", "adapter": a["adapter"],
            "sourceId": "sheca-repository", "previous": metadata(a),
            "current": metadata(b), "status": status, "bodyChanged": body_changed,
            "projectedRowsChanged": bool(changes), "exactDuplicateCountChanged": duplicate_change,
            "reviewSuggested": review, "counts": counts,
            "ambiguousPublishedSHA1": ambiguous, "changes": changes,
            "coverage": "PARSED_CLAIMS_ONLY_NOT_AUTHENTICATED_COMPLETENESS",
            "certificateIdentity": "NOT_ESTABLISHED", "sourceAuthentication": "NOT_ESTABLISHED",
            "trustStatus": "NOT_ESTABLISHED"}


def read_observation(path):
    with path.open("rb") as handle:
        return handle.read(MAX_OBSERVATION + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--previous-sha256", required=True)
    parser.add_argument("--current-sha256", required=True)
    args = parser.parse_args()
    try:
        report = compare(read_observation(args.previous), args.previous_sha256,
                         read_observation(args.current), args.current_sha256)
        # Serialize completely before writing any result.
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print("SHECA semantic diff: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
