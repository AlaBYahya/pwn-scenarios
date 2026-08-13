#!/usr/bin/env python3
"""Collect real, disclosed Immunefi smart-contract bug bounty writeups from a
curated community-maintained list (sayan011/Immunefi-bug-bounty-writeups-list
on GitHub -- a markdown table of bounty/severity/protocol+writeup-link/whitehat).

There's no dedicated vulnerability-class tag in this table, so the URL slug
(which for Medium/Mirror postmortems is usually descriptive, e.g.
"wormhole-uninitialized-proxy-bugfix-review") is split into words and used as
the classification tag field, the same role `bugs` plays for other
aggregated_writeup sources -- weaker signal than a real tag, comparable to
what RSS/blog titles get.

Usage:
    python3 collect_immunefi.py --out ../data/raw/immunefi.jsonl
"""
import argparse
import json
import re
import sys
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/sayan011/Immunefi-bug-bounty-writeups-list/main/README.md"

ROW_RE = re.compile(
    r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*\[([^\]]+)\]\(([^)\s]+)\)\s*\|\s*(?:\[([^\]]+)\]\([^)]*\)|-)\s*\|",
    re.MULTILINE,
)


def slug_words(url):
    # Last path segment, Medium/Mirror-style: strip trailing hash IDs, split on '-'.
    tail = url.rstrip("/").split("/")[-1]
    words = [w for w in tail.split("-") if w and not re.fullmatch(r"[0-9a-f]{6,}", w)]
    return " ".join(words)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-url", default=SOURCE_URL)
    ap.add_argument("--out", default="../data/raw/immunefi.jsonl")
    args = ap.parse_args()

    req = urllib.request.Request(args.source_url, headers={"user-agent": "pwn-scenarios-collector/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", errors="replace")

    total = 0
    seen_urls = set()
    with open(args.out, "w") as out_f:
        for m in ROW_RE.finditer(text):
            bounty_raw, severity_raw, protocol, url, whitehat = m.groups()
            if url in seen_urls or protocol.strip().lower() == "protocol name + write-up link":
                continue
            seen_urls.add(url)
            bounty = bounty_raw.strip()
            if bounty.lower() in ("", "-", "not paid(out of scope)", "not paid"):
                bounty = None
            record = {
                "source_platform": "aggregated_writeup",
                "title": protocol.strip(),
                "url": url,
                "programs": [protocol.strip()],
                "authors": [whitehat] if whitehat else [],
                "publication_date": None,
                "bounty": bounty,
                "bugs": slug_words(url).split(),
            }
            out_f.write(json.dumps(record) + "\n")
            total += 1

    print(f"Wrote {total} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
