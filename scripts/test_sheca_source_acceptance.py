import json
import unittest

from sheca_source_acceptance import acceptance
from test_sheca_source_diff import page, capture


def entry(id, sha, label, role="ROOT", status="LISTED", date="2036-12-31"):
    return {"id": id, "publishedSHA1": sha, "label": label, "publishedRole": role,
            "publishedStatus": status, "publishedValidUntil": date,
            "redistributionStatus": "NOT_REVIEWED"}


def baseline(entries):
    return json.dumps({"schemaVersion": "1", "authorityId": "cn.sheca",
                       "repositoryURL": "https://www.sheca.com/repository",
                       "coverage": "SELECTED_RESEARCH_ROWS", "observedOn": "2026-11-27",
                       "entries": entries}).encode()


class AcceptanceTest(unittest.TestCase):
    def test_matching_selected_fields_and_unlisted(self):
        b = baseline([entry("root", "a"*40, "Root")])
        r = acceptance(*capture(page()), b)
        self.assertEqual(r["counts"]["matching"], 1)
        self.assertEqual(r["unlistedFingerprintClaimCount"], 2)
        self.assertEqual(r["status"], "HUMAN_REVIEW_REQUIRED")
        self.assertFalse(r["liveProfileAccepted"])
        self.assertNotIn("/test.pem", json.dumps(r))

    def test_missing_mismatch_ambiguous_and_disuse(self):
        b = baseline([entry("root", "a"*40, "Root"),
                      entry("intermediate", "b"*40, "Different", "INTERMEDIATE"),
                      entry("old", "c"*40, "Old", "INTERMEDIATE", "DISUSE"),
                      entry("missing", "d"*40, "Missing")])
        html = page(root=[("Root", "a"*40), ("Alias", "a"*40)])
        r = acceptance(*capture(html), b)
        self.assertEqual(r["counts"], {"baselineRows": 4, "matching": 1, "missing": 1,
                                       "fieldMismatch": 1, "ambiguous": 1})
        self.assertEqual(r["sectionRowCounts"], {"ROOT": 2, "INTERMEDIATE": 1, "DISUSE": 1})
        self.assertEqual(r["trustStatus"], "NOT_ESTABLISHED")

    def test_wrong_pin_bad_page_bad_baseline(self):
        b = baseline([entry("root", "a"*40, "Root")])
        raw, pin = capture(page())
        with self.assertRaises(ValueError): acceptance(raw, "0"*64, b)
        with self.assertRaises(ValueError): acceptance(*capture("<html>challenge</html>"), b)
        duplicate = baseline([entry("root", "a"*40, "Root"), entry("alias", "a"*40, "Alias")])
        with self.assertRaises(ValueError): acceptance(raw, pin, duplicate)

    def test_baseline_hash_and_determinism(self):
        b = baseline([entry("root", "a"*40, "Root")])
        raw, pin = capture(page())
        r = acceptance(raw, pin, b)
        self.assertEqual(r, acceptance(raw, pin, b))
        self.assertNotEqual(r["baselineSHA256"], acceptance(raw, pin, b+b"\n")["baselineSHA256"])


if __name__ == "__main__":
    unittest.main()
