#!/usr/bin/env python3
"""Collect writeup links from curated "awesome list"-style GitHub repos.

These are community-maintained lists of writeup links -- the same
link+metadata pattern as the Pentester Land collector, just from different
curators. Four formats show up in the wild and all are handled:

  - Markdown list items:  `- [Title](url)`
  - HTML anchors inside markdown tables: `| <a href="url">Title</a> | ... |`
    (used by insecrez/Bug-bounty-Writeups; a plain `[title](url)` regex
    finds zero matches against this format, which is a real trap -- it
    looks empty/tools-only if you only check the markdown-link pattern)
  - A bespoke templated markdown line: `- **[DATE - $BOUNTY]** [Title](url)
    by [Author](author_url)` (used by Facebook-BugBounty-Writeups)
  - A plain CSV file with explicit columns (used by
    awesome-google-vrp-writeups' writeups.csv) -- the cleanest possible
    format, no regex guessing needed at all

Heavy overlap with Pentester Land/HackerOne is expected and harmless:
normalize.py dedups by URL automatically, so this only ever contributes
genuinely new links.

Usage:
    python3 collect_curated_lists.py --out ../data/raw/curated_lists.jsonl
"""
import argparse
import csv
import html
import io
import json
import re
import sys
import urllib.request

MARKDOWN_SOURCES = [
    ("devanshbatham/Awesome-Bugbounty-Writeups", "https://raw.githubusercontent.com/devanshbatham/Awesome-Bugbounty-Writeups/master/README.md"),
    ("ngalongc/bug-bounty-reference", "https://raw.githubusercontent.com/ngalongc/bug-bounty-reference/master/README.md"),
    ("corca-ai/awesome-llm-security", "https://raw.githubusercontent.com/corca-ai/awesome-llm-security/main/README.md"),
]

HTML_TABLE_SOURCES = [
    ("insecrez/Bug-bounty-Writeups", "https://raw.githubusercontent.com/insecrez/Bug-bounty-Writeups/master/README.md"),
]

# `- **[Mar 11 - $???]** [Title](url) by [Author](author_url)`
TEMPLATED_SOURCES = [
    ("jaiswalakshansh/Facebook-BugBounty-Writeups", "https://raw.githubusercontent.com/jaiswalakshansh/Facebook-BugBounty-Writeups/master/README.md"),
]

CSV_SOURCES = [
    ("xdavidhu/awesome-google-vrp-writeups", "https://raw.githubusercontent.com/xdavidhu/awesome-google-vrp-writeups/master/writeups.csv"),
]

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
YEAR_HEADING_RE = re.compile(r"^(19|20)\d{2}")
MD_LINK_RE = re.compile(r"^\s*[-*]\s*\[([^\]]+)\]\((https?://[^\s)]+)\)")
HTML_ANCHOR_RE = re.compile(r'<a[^>]*?href="(https?://[^"]+)"[^>]*>([^<]*)', re.IGNORECASE)
TEMPLATED_RE = re.compile(
    r"^\s*-\s*\*\*\[([A-Za-z]+ \d{1,2})\s*-\s*(\$[\d,]+|\$\?+)\]\*\*\s*"
    r"\[([^\]]+)\]\((https?://[^\s)]+)\)"
    r"(?:\s+by\s+\[([^\]]+)\])?"
)


def parse_markdown(text):
    """Yield a record dict for each `- [Title](url)` list item."""
    section = None
    for line in text.splitlines():
        h = HEADING_RE.match(line)
        if h:
            section = re.sub(r"[`*_]", "", h.group(2)).strip()
            continue
        m = MD_LINK_RE.match(line)
        if m:
            yield {"title": m.group(1).strip(), "url": m.group(2).strip(), "tag": section}


def parse_html_table(text):
    """Yield a record dict for each `<a href="url">Title</a>` found in a
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
                yield {"title": title, "url": url.strip(), "tag": tag}


def parse_templated(text):
    """Yield a record dict for `- **[DATE - $BOUNTY]** [Title](url) by [Author](url)` lines."""
    year = None
    for line in text.splitlines():
        h = HEADING_RE.match(line)
        if h:
            heading = h.group(2).strip()
            if YEAR_HEADING_RE.match(heading):
                year = heading[:4]
            continue
        m = TEMPLATED_RE.match(line)
        if not m:
            continue
        date_str, bounty, title, url, author = m.groups()
        bounty = None if bounty in ("$???", "$??") else bounty
        publication_date = f"{year}-{date_str}" if year else None
        yield {"title": title.strip(), "url": url.strip(), "author": author, "bounty": bounty, "date": publication_date}


def parse_csv_writeups(text):
    """Yield a record dict for each row of a `date,bounty,title,url,author,author-url,type,...` CSV."""
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        title = (row.get("title") or "").strip()
        url = (row.get("url") or "").strip()
        if not title or not url:
            continue
        bounty = row.get("bounty")
        bounty = None if not bounty or bounty == "?" else bounty
        date = row.get("date")
        date = None if not date or date == "?" else date
        author = row.get("author")
        author = None if not author or author == "?" else author
        yield {"title": title, "url": url, "author": author, "bounty": bounty, "date": date}


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
            + [(n, u, parse_templated) for n, u in TEMPLATED_SOURCES]
            + [(n, u, parse_csv_writeups) for n, u in CSV_SOURCES]
        ):
            text = fetch(repo_name, raw_url)
            if text is None:
                continue

            count_this_source = 0
            for item in parser(text):
                url = item["url"]
                if url in seen_urls:
                    continue
                if "github.com" in url and repo_name in url:
                    continue  # skip self-referential TOC anchor links rendered as full URLs
                seen_urls.add(url)
                record = {
                    "source_platform": "aggregated_writeup",
                    "title": item["title"],
                    "url": url,
                    "authors": [item["author"]] if item.get("author") else [],
                    "programs": [],
                    "bugs": [item["tag"]] if item.get("tag") else [],
                    "bounty": item.get("bounty"),
                    "publication_date": item.get("date"),
                    "curated_list_source": repo_name,
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                total += 1
                count_this_source += 1
            print(f"{repo_name}: {count_this_source} links", file=sys.stderr)

    print(f"Wrote {total} unique records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
