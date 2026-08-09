#!/usr/bin/env python3
"""Collect writeup links from curated "awesome list"-style GitHub READMEs.

These are community-maintained lists of writeup links organized under
vulnerability-class headings -- the same link+metadata pattern as the
Pentester Land collector, just from different curators. Two link formats
show up in the wild and both are handled:

  - Markdown list items:  `- [Title](url)`
  - HTML anchors inside markdown tables: `| <a href="url">Title</a> | ... |`
    (used by insecrez/Bug-bounty-Writeups; a plain `[title](url)` regex
    finds zero matches against this format, which is a real trap -- it
    looks empty/tools-only if you only check the markdown-link pattern)

Heavy overlap with Pentester Land/HackerOne is expected and harmless:
normalize.py dedups by URL automatically, so this only ever contributes
genuinely new links.

Usage:
    python3 collect_curated_lists.py --out ../data/raw/curated_lists.jsonl
"""
import argparse
import html
import json
import re
import sys
import urllib.request

MARKDOWN_SOURCES = [
    ("devanshbatham/Awesome-Bugbounty-Writeups", "https://raw.githubusercontent.com/devanshbatham/Awesome-Bugbounty-Writeups/master/README.md"),
    ("ngalongc/bug-bounty-reference", "https://raw.githubusercontent.com/ngalongc/bug-bounty-reference/master/README.md"),
]

HTML_TABLE_SOURCES = [
    ("insecrez/Bug-bounty-Writeups", "https://raw.githubusercontent.com/insecrez/Bug-bounty-Writeups/master/README.md"),
]

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
MD_LINK_RE = re.compile(r"^\s*[-*]\s*\[([^\]]+)\]\((https?://[^\s)]+)\)")
HTML_ANCHOR_RE = re.compile(r'<a[^>]*?href="(https?://[^"]+)"[^>]*>([^<]*)', re.IGNORECASE)


def parse_markdown(text):
    """Yield (title, url, section_tag) for each `- [Title](url)` list item."""
    section = None
    for line in text.splitlines():
        h = HEADING_RE.match(line)
        if h:
            section = re.sub(r"[`*_]", "", h.group(2)).strip()
            continue
        m = MD_LINK_RE.match(line)
        if m:
            title, url = m.group(1).strip(), m.group(2).strip()
            yield title, url, section


def parse_html_table(text):
    """Yield (title, url, tag) for each `<a href="url">Title</a>` found in a
    markdown table row, tagged by either a leading category cell (e.g. the
    "AI Hacking" column in insecrez's AI section) or the current heading."""
    section = None
    for line in text.splitlines():
        h = HEADING_RE.match(line)
        if h:
            section = re.sub(r"[`*_:]", "", h.group(2)).strip()
            continue
        if "<a" not in line.lower():
            continue

        category = None
        for cell in line.split("|"):
            cell = cell.strip()
            if not cell:
                continue
            if "<a" in cell.lower():
                break
            if len(cell) <= 40:
                category = cell
            break

        tag = category or section
        for url, title in HTML_ANCHOR_RE.findall(line):
            title = html.unescape(title).strip()
            if title and url:
                yield title, url.strip(), tag


def fetch(name, url):
    try:
        req = urllib.request.Request(url, headers={"user-agent": "pwn-scenarios-collector/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"fetch failed for {name}: {e}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/raw/curated_lists.jsonl")
    args = ap.parse_args()

    seen_urls = set()
    total = 0
    with open(args.out, "w") as f:
        for repo_name, raw_url, parser in (
            [(n, u, parse_markdown) for n, u in MARKDOWN_SOURCES]
            + [(n, u, parse_html_table) for n, u in HTML_TABLE_SOURCES]
        ):
            text = fetch(repo_name, raw_url)
            if text is None:
                continue

            count_this_source = 0
            for title, url, section in parser(text):
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
