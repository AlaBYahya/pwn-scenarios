#!/usr/bin/env python3
"""Collect from Zero Day Initiative's public RSS feed of published advisories.

ZDI (Trend Micro's vulnerability purchase / coordinated-disclosure program,
the organization behind Pwn2Own) publishes each advisory with a real CVE ID
and CVSS score in the description, and a title that names the vulnerability
type in prose (e.g. "Cisco Identity Services Engine invokeScript Command
Injection Remote Code Execution Vulnerability"). We strip the leading
"ZDI-XX-NNN: " prefix and trailing "Vulnerability" suffix and use the
remainder as the classification tag field.

Usage:
    python3 collect_zdi.py --out ../data/raw/zdi.jsonl
"""
import argparse
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

FEED_URL = "https://www.zerodayinitiative.com/rss/published/"

TITLE_RE = re.compile(r"^ZDI-[\w-]+:\s*(.+?)\s*Vulnerability\s*$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def clean(text):
    return re.sub(r"\s+", " ", text or "").strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed-url", default=FEED_URL)
    ap.add_argument("--out", default="../data/raw/zdi.jsonl")
    args = ap.parse_args()

    req = urllib.request.Request(args.feed_url, headers={"user-agent": "pwn-scenarios-collector/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        xml_text = resp.read()
    root = ET.fromstring(xml_text)

    total = 0
    with open(args.out, "w") as out_f:
        for item in root.findall(".//item"):
            raw_title = clean(item.findtext("title"))
            link = clean(item.findtext("link"))
            description = item.findtext("description") or ""
            pub_date = item.findtext("pubDate")
            if not raw_title or not link:
                continue
            m = TITLE_RE.match(raw_title)
            vuln_phrase = m.group(1) if m else raw_title
            cves = CVE_RE.findall(description)
            record = {
                "source_platform": "aggregated_writeup",
                "title": raw_title,
                "url": link,
                "authors": [],
                "programs": ["ZDI"],
                "bugs": [vuln_phrase],
                "bounty": None,
                "publication_date": pub_date,
                "cve_ids": cves,
            }
            out_f.write(json.dumps(record) + "\n")
            total += 1

    print(f"Wrote {total} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
