#!/usr/bin/env python3
"""Offline, conservative SHECA listing projection. Never fetch or grant trust."""
import argparse
import base64
import datetime as dt
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys

MAX_OBSERVATION = 3 << 20
MAX_BODY = 2 << 20
MAX_ROWS = 2048
SOURCE = {"id": "sheca-repository", "authority": "SHECA",
          "url": "https://www.sheca.com/repository", "kind": "CATALOG"}
SECTIONS = {"Root Certificates / 根证书": "ROOT",
            "Intermediate Certificates / 中级证书": "INTERMEDIATE",
            "Disuse Certificates / 停用证书": "DISUSE"}
IGNORED_TAGS = ("script", "style", "template", "noscript")
HEADER = ["Name / 名称", "Fingerprint / 指纹（SHA1）", "Valid Until / 有效期至", "Links / 链接"]
MONTHS = {m: i for i, m in enumerate("January February March April May June July August September October November December".split(), 1)}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def observation(data, pin):
    if not re.fullmatch(r"[0-9a-f]{64}", pin) or len(data) > MAX_OBSERVATION or digest(data) != pin:
        raise ValueError("observation size or independent pin mismatch")
    o = json.loads(data, object_pairs_hook=unique_object)
    keys = {"schemaVersion", "source", "recordedAt", "mode", "bodySHA256", "bodyBytes", "raw", "sourceAuthentication", "trustStatus"}
    if not isinstance(o, dict) or set(o) not in (keys, keys | {"mediaType"}):
        raise ValueError("unexpected observation fields")
    if o["schemaVersion"] != "1" or o["source"] != SOURCE or o["sourceAuthentication"] != "NOT_ESTABLISHED" or o["trustStatus"] != "NOT_ESTABLISHED":
        raise ValueError("unexpected observation identity or trust status")
    if (o["mode"] == "HTTPS_RESPONSE" and o.get("mediaType") not in ("text/html", "application/xhtml+xml")) or (o["mode"] == "LOCAL_INPUT" and "mediaType" in o) or o["mode"] not in ("HTTPS_RESPONSE", "LOCAL_INPUT"):
        raise ValueError("HTML observation required")
    if not isinstance(o["recordedAt"], str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", o["recordedAt"]):
        raise ValueError("UTC observation time required")
    dt.datetime.fromisoformat(o["recordedAt"].replace("Z", "+00:00"))
    raw = base64.b64decode(o["raw"], validate=True)
    if not 0 < len(raw) <= MAX_BODY or type(o["bodyBytes"]) is not int or len(raw) != o["bodyBytes"] or digest(raw) != o["bodySHA256"]:
        raise ValueError("body length or digest mismatch")
    return o, raw.decode("utf-8-sig", errors="strict")


def clean(text):
    return " ".join(text.split())


def fingerprint(text):
    value = text.strip("\u200e\u200f ").lower()
    if re.fullmatch(r"(?:[0-9a-f]{2}:){19}[0-9a-f]{2}", value):
        value = value.replace(":", "")
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("invalid published SHA-1")
    return value


def date(text):
    match = re.fullmatch(r"([A-Za-z]+) (\d{1,2}), (\d{4})", text)
    if not match or match[1] not in MONTHS:
        raise ValueError("unrecognized published date")
    return dt.date(int(match[3]), MONTHS[match[1]], int(match[2])).isoformat()


class Tables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.recent = ""
        self.pending = None
        self.section = None
        self.in_table = False
        self.row = None
        self.cell = None
        self.table_rows = []
        self.sections = {}
        self.ignored = []
        self.count = 0

    def handle_starttag(self, tag, attrs):
        if self.ignored or tag in IGNORED_TAGS:
            if tag in IGNORED_TAGS:
                if len(self.ignored) >= 32:
                    raise ValueError("ignored element nesting limit")
                self.ignored.append(tag)
            return
        if tag == "table":
            if self.in_table:
                raise ValueError("nested table not supported")
            self.in_table = True
            self.section, self.pending = self.pending, None
            self.recent = ""
            self.table_rows = []
        elif self.in_table and tag == "tr":
            if self.row is not None:
                raise ValueError("unclosed row")
            self.row = []
        elif self.in_table and tag in ("td", "th"):
            if self.row is None or self.cell is not None or any(k in ("colspan", "rowspan") and v != "1" for k, v in attrs):
                raise ValueError("ambiguous table cell")
            self.cell = {"text": "", "links": [], "tag": tag}
        elif self.cell is not None and tag == "a":
            hrefs = [v for k, v in attrs if k == "href"]
            if len(hrefs) != 1 or not hrefs[0] or len(hrefs[0]) > 2048 or len(self.cell["links"]) >= 8:
                raise ValueError("unrecognized link entry")
            self.cell["links"].append(hrefs[0])
        elif self.cell is not None and tag == "br":
            self.handle_data(" ")

    def handle_endtag(self, tag):
        if self.ignored:
            if tag in IGNORED_TAGS:
                if tag != self.ignored[-1]:
                    raise ValueError("mismatched ignored element end")
                self.ignored.pop()
            return
        if not self.in_table:
            return
        if tag in ("td", "th"):
            if self.cell is None or self.cell["tag"] != tag:
                raise ValueError("unexpected cell end")
            self.cell["text"] = clean(self.cell["text"])
            self.row.append(self.cell)
            self.cell = None
            if len(self.row) > 16:
                raise ValueError("column limit")
        elif tag == "tr":
            if self.cell is not None or self.row is None or not self.row:
                raise ValueError("incomplete row")
            self.count += 1
            if self.count > MAX_ROWS:
                raise ValueError("row limit")
            self.table_rows.append(self.row)
            self.row = None
        elif tag == "table":
            if self.row is not None or self.cell is not None:
                raise ValueError("incomplete table")
            self.in_table = False
            matches = bool(self.table_rows) and [c["text"] for c in self.table_rows[0]] == HEADER
            if self.section is not None or matches:
                if not matches or self.section is None or self.section in self.sections or len(self.table_rows) < 2:
                    raise ValueError("unrecognized, duplicate or empty certificate section")
                self.sections[self.section] = self.table_rows[1:]
            self.section = None
            self.recent = ""

    def handle_data(self, data):
        if self.ignored:
            return
        if self.cell is not None:
            self.cell["text"] += data
            if len(self.cell["text"]) > 4096:
                raise ValueError("cell text limit")
        elif not self.in_table:
            self.recent = clean(self.recent + " " + data)[-256:]
            for heading, section in SECTIONS.items():
                if self.recent.endswith(heading):
                    self.pending = section

    def finish(self):
        self.close()
        if self.in_table or self.ignored or set(self.sections) != set(SECTIONS.values()):
            raise ValueError("all three complete certificate sections required")
        rows = []
        for section, table in self.sections.items():
            for cells in table:
                if len(cells) != 4 or any(c["links"] for c in cells[:3]) or not cells[0]["text"] or len(cells[0]["text"]) > 512 or not cells[3]["links"]:
                    raise ValueError("unrecognized certificate row")
                rows.append({"section": section, "label": cells[0]["text"], "publishedSHA1": fingerprint(cells[1]["text"]), "publishedValidUntil": date(cells[2]["text"]), "linkText": cells[3]["text"], "observedHrefs": sorted(set(cells[3]["links"]))})
        return rows


def project(data, pin):
    o, html = observation(data, pin)
    parser = Tables()
    parser.feed(html)
    rows = parser.finish()
    # Identical observations may be collapsed; differing rows with the same
    # SHA-1 (or label) are retained, never interpreted as unique identities.
    unique = {json.dumps(r, ensure_ascii=False, sort_keys=True): r for r in rows}
    ordered = [unique[key] for key in sorted(unique)]
    counts = {}
    for row in ordered:
        counts[row["publishedSHA1"]] = counts.get(row["publishedSHA1"], 0) + 1
    return {"schemaVersion": "1", "adapter": "SHECA_TABLE_V1", "observationSHA256": pin,
            "recordedAt": o["recordedAt"], "mode": o["mode"], "bodySHA256": o["bodySHA256"],
            "status": "EXTRACTED_REVIEW_REQUIRED", "coverage": "PARSED_TABLE_ROWS_NOT_AUTHENTICATED_COMPLETENESS",
            "rows": ordered, "exactDuplicateRows": len(rows) - len(ordered),
            "repeatedPublishedSHA1": sorted(k for k, n in counts.items() if n > 1),
            "sourceAuthentication": "NOT_ESTABLISHED", "trustStatus": "NOT_ESTABLISHED"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("observation", type=Path)
    p.add_argument("--sha256", required=True)
    args = p.parse_args()
    try:
        with args.observation.open("rb") as f:
            data = f.read(MAX_OBSERVATION + 1)
        print(json.dumps(project(data, args.sha256), ensure_ascii=False, indent=2))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print("SHECA adapter: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
