#!/usr/bin/env python3
"""Cross-check a pinned SHECA HTML capture against selected research rows."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys

from sheca_source_adapter import MAX_OBSERVATION, SOURCE, digest, project, unique_object

MAX_BASELINE = 256 << 10
DEFAULT_BASELINE = Path(__file__).resolve().parents[1] / "pkg/sources/sheca.json"


def baseline(data):
    if not 0 < len(data) <= MAX_BASELINE:
        raise ValueError("baseline size limit")
    b = json.loads(data, object_pairs_hook=unique_object)
    if (b["schemaVersion"], b["authorityId"], b["repositoryURL"], b["coverage"]) != (
        "1", "cn.sheca", SOURCE["url"], "SELECTED_RESEARCH_ROWS"
    ):
        raise ValueError("unexpected SHECA baseline identity")
    dt.date.fromisoformat(b["observedOn"])
    entries = b["entries"]
    if not isinstance(entries, list) or not 0 < len(entries) <= 1000:
        raise ValueError("baseline entry count limit")
    seen_ids, seen_sha = set(), set()
    for e in entries:
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", e["id"])
                or not re.fullmatch(r"[a-f0-9]{40}", e["publishedSHA1"])
                or e["id"] in seen_ids or e["publishedSHA1"] in seen_sha
                or e["publishedRole"] not in ("ROOT", "INTERMEDIATE")
                or e["publishedStatus"] not in ("LISTED", "DISUSE")
                or e["redistributionStatus"] != "NOT_REVIEWED"
                or not isinstance(e["label"], str) or not e["label"]):
            raise ValueError("invalid or duplicate baseline entry")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", e["publishedValidUntil"]):
            raise ValueError("invalid baseline validity date")
        dt.date.fromisoformat(e["publishedValidUntil"])
        seen_ids.add(e["id"])
        seen_sha.add(e["publishedSHA1"])
    return b


def acceptance(data, pin, baseline_data):
    p = project(data, pin)  # never consume editable projection JSON
    b = baseline(baseline_data)
    grouped = {}
    section_counts = {"ROOT": 0, "INTERMEDIATE": 0, "DISUSE": 0}
    for row in p["rows"]:
        grouped.setdefault(row["publishedSHA1"], []).append(row)
        section_counts[row["section"]] += 1
    counts = {"baselineRows": len(b["entries"]), "matching": 0,
              "missing": 0, "fieldMismatch": 0, "ambiguous": 0}
    results = []
    known = set()
    for entry in sorted(b["entries"], key=lambda e: e["id"]):
        sha = entry["publishedSHA1"]
        known.add(sha)
        expected = {"section": "DISUSE" if entry["publishedStatus"] == "DISUSE" else entry["publishedRole"],
                    "label": entry["label"], "publishedValidUntil": entry["publishedValidUntil"]}
        rows = grouped.get(sha, [])
        # Exclude hrefs from the shareable summary. The private projection
        # retains the complete literals for operator review.
        observed = [{k: row[k] for k in expected} for row in rows]
        mismatches = []
        if not rows:
            status, key = "BASELINE_CLAIM_NOT_OBSERVED", "missing"
        elif len(rows) > 1:
            status, key = "AMBIGUOUS_PUBLISHED_SHA1", "ambiguous"
        else:
            mismatches = [k for k in expected if observed[0][k] != expected[k]]
            status, key = ("FIELDS_DIFFER", "fieldMismatch") if mismatches else ("SELECTED_FIELDS_MATCH", "matching")
        counts[key] += 1
        results.append({"listingId": entry["id"], "publishedSHA1": sha, "status": status,
                        "expected": expected, "observed": observed, "mismatchedFields": mismatches})
    unlisted = sorted(set(grouped) - known)
    return {
        "schemaVersion": "1", "adapter": p["adapter"], "sourceId": SOURCE["id"],
        "observationSHA256": pin, "bodySHA256": p["bodySHA256"],
        "recordedAt": p["recordedAt"], "mode": p["mode"],
        "baselineSHA256": digest(baseline_data), "baselineObservedOn": b["observedOn"],
        "status": "HUMAN_REVIEW_REQUIRED", "counts": counts,
        "projectedDistinctRows": len(p["rows"]), "sectionRowCounts": section_counts,
        "projectedFingerprintGroups": len(grouped), "exactDuplicateRows": p["exactDuplicateRows"],
        "ambiguousPublishedSHA1": p["repeatedPublishedSHA1"],
        "unlistedFingerprintClaimCount": len(unlisted), "unlistedFingerprintClaims": unlisted,
        "baselineResults": results,
        "coverage": "SELECTED_RESEARCH_BASELINE_CROSSCHECK_ONLY",
        "liveProfileAccepted": False, "sourceAuthentication": "NOT_ESTABLISHED",
        "certificateIdentity": "NOT_ESTABLISHED", "trustStatus": "NOT_ESTABLISHED",
    }


def read_bounded(path, limit):
    with path.open("rb") as f:
        return f.read(limit + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observation", type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        result = acceptance(read_bounded(args.observation, MAX_OBSERVATION), args.sha256,
                            read_bounded(DEFAULT_BASELINE, MAX_BASELINE))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print("SHECA acceptance: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
