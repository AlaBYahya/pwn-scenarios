#!/usr/bin/env python3
"""Collect writeup metadata from publisher-provided RSS feeds.

Covers Medium publications on a custom domain (which expose a standard
RSS 2.0 feed at `/feed`) and other security blogs/platforms that publish
their own RSS feed -- an explicitly publisher-provided syndication
mechanism, not a scrape. We only take title/link/author/date/categories
from each item, never the full article body (each <item> also includes
<content:encoded> with the complete HTML text, which we deliberately never
read past the metadata fields -- same no-full-text policy as every other
source).

Caveat: most of these feeds only return the ~10-20 most recent posts per
publication, not a full archive. Re-running this periodically (e.g. via a
scheduled job) accumulates more over time as new articles get published and
old ones age out of the "recent" window; normalize.py's URL dedup means
re-running never produces duplicates.

Usage:
    python3 collect_rss_feeds.py --out ../data/raw/rss_feeds.jsonl
"""
import argparse
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

FEEDS = [
    ("InfoSec Write-ups", "https://infosecwriteups.com/feed"),
    ("System Weakness", "https://systemweakness.com/feed"),
    ("OSINT Team", "https://osintteam.blog/feed"),
    ("Intigriti Blog", "https://www.intigriti.com/blog/feed"),
]

NS = {"dc": "http://purl.org/dc/elements/1.1/"}


def clean_title(title):
    return re.sub(r"\s+", " ", title or "").strip()


def parse_feed(xml_text):
    root = ET.fromstring(xml_text)
    items = []
    for item in root.findall(".//item"):
        title = clean_title(item.findtext("title"))
        link = (item.findtext("link") or "").split("?")[0]
        if not title or not link:
            continue
        author_el = item.find("dc:creator", NS)
        author = author_el.text.strip() if author_el is not None and author_el.text else None
        categories = [c.text.strip() for c in item.findall("category") if c.text]
        pub_date = item.findtext("pubDate")
        items.append({"title": title, "link": link, "author": author, "categories": categories, "pub_date": pub_date})
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/raw/rss_feeds.jsonl")
    args = ap.parse_args()

    total = 0
    with open(args.out, "w") as f:
        for pub_name, feed_url in FEEDS:
            try:
                req = urllib.request.Request(feed_url, headers={"user-agent": "pwn-scenarios-collector/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    xml_text = resp.read()
            except Exception as e:
                print(f"fetch failed for {pub_name} ({feed_url}): {e}", file=sys.stderr)
                continue

            try:
                items = parse_feed(xml_text)
            except ET.ParseError as e:
                print(f"parse failed for {pub_name}: {e}", file=sys.stderr)
                continue

            for it in items:
                record = {
                    "source_platform": "aggregated_writeup",
                    "title": it["title"],
                    "url": it["link"],
                    "authors": [it["author"]] if it["author"] else [],
                    "programs": [],
                    "bugs": it["categories"],
                    "bounty": None,
                    "publication_date": it["pub_date"],
                    "feed_source": pub_name,
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                total += 1
            print(f"{pub_name}: {len(items)} items", file=sys.stderr)

    print(f"Wrote {total} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
