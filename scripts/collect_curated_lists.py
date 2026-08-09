#!/usr/bin/env python3
"""Collect writeup links from curated "awesome list"-style GitHub READMEs.

These are community-maintained markdown lists of writeup links organized
under vulnerability-class headings (`## SQL Injection` followed by
`- [Title](url)` items) -- the same link+metadata pattern as the Pentester
Land collector, just from different curators. Heavy overlap with Pentester
Land is expected and harmless: normalize.py dedups by URL automatically, so
this only ever contributes genuinely new links.

Usage:
    python3 collect_curated_lists.py --out ../data/raw/curated_lists.jsonl
"""
import argparse
import json
import re
import sys
import urllib.request

SOURCES = [
    ("devanshbatham/Awesome-Bugbounty-Writeups", "https://raw.githubusercontent.com/devanshbatham/Awesome-Bugbounty-Writeups/master/README.md"),
    ("ngalongc/bug-bounty-reference", "https://raw.githubusercontent.com/ngalongc/bug-bounty-reference/master/README.md"),
]

HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")
LINK_RE = re.compile(r"^\s*[-*]\s*\[([^\]]+)\]\((https?://[^\s)]+)\)")


def parse_markdown(text):
    """Yield (title, url, section_tag) for each markdown link list item."""
    section = None
    for line in text.splitlines():
        h = HEADING_RE.match(line)
        if h:
            section = re.sub(r"[`*_]", "", h.group(1)).strip()
            continue
        m = LINK_RE.match(line)
        if m:
            title, url = m.group(1).strip(), m.group(2).strip()
            yield title, url, section


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/raw/curated_lists.jsonl")
    args = ap.parse_args()

    seen_urls = set()
    total = 0
    with open(args.out, "w") as f:
        for repo_name, raw_url in SOURCES:
            try:
                req = urllib.request.Request(raw_url, headers={"user-agent": "pwn-scenarios-collector/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
            except Exception as e:
                print(f"fetch failed for {repo_name}: {e}", file=sys.stderr)
                continue

            count_this_source = 0
            for title, url, section in parse_markdown(text):
                if url in seen_urls:
                    continue
                if "github.com" in url and repo_name in url:
                    continue  # skip self-referential TOC anchor links rendered as full URLs
                seen_urls.add(url)
                record = {
                    "source_platform": "aggregated_writeup",
                    "title": title,
                    "url": url,
                    "authors": [],
                    "programs": [],
                    "bugs": [section] if section else [],
                    "bounty": None,
                    "publication_date": None,
                    "curated_list_source": repo_name,
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                total += 1
                count_this_source += 1
            print(f"{repo_name}: {count_this_source} links", file=sys.stderr)

    print(f"Wrote {total} unique records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
