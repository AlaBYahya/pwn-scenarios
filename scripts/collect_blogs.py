#!/usr/bin/env python3
"""Collect writeup metadata from individual security researcher blogs.

Two collection patterns, both metadata-only (title + link + date; never the
article body):

1. Atom/RSS feed blogs (e.g. Jekyll/Hexo-generated) -- title/link/published
   date come straight from the feed's own XML, no extra page fetches needed.
2. Sitemap-only blogs -- the sitemap gives real post URLs but no titles, so
   each post page is fetched once and only its <meta property="og:title">
   (falling back to <title>) is read; the page body is discarded immediately
   after. Only used for sites whose robots.txt explicitly allows crawling
   (`Allow: /`) and that publish their own sitemap for exactly this kind of
   discovery.

Usage:
    python3 collect_blogs.py --out ../data/raw/blogs.jsonl
"""
import argparse
import html
import json
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

ATOM_FEEDS = [
    ("Chybeta", "https://chybeta.github.io/atom.xml"),
]

SITEMAP_BLOGS = [
    {"name": "Embrace The Red", "sitemap": "https://embracethered.com/blog/sitemap.xml", "include": r"/posts/\d{4}/[^/]+/$", "max_pages": 250},
    {"name": "Evan Connelly", "sitemap": "https://evanconnelly.com/sitemap.xml", "include": r"/post/[^/]+/$", "max_pages": 30},
]

ATOM_NS = {"a": "http://www.w3.org/2005/Atom"}
UA = {"user-agent": "pwn-scenarios-collector/1.0"}


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def collect_atom_feed(name, url):
    try:
        raw = fetch(url, timeout=30)
    except Exception as e:
        print(f"fetch failed for {name}: {e}", file=sys.stderr)
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        print(f"parse failed for {name}: {e}", file=sys.stderr)
        return []

    records = []
    for entry in root.findall("a:entry", ATOM_NS) or root.findall(".//entry"):
        title_el = entry.find("a:title", ATOM_NS) if entry.find("a:title", ATOM_NS) is not None else entry.find("title")
        link_el = entry.find("a:link", ATOM_NS) if entry.find("a:link", ATOM_NS) is not None else entry.find("link")
        pub_el = entry.find("a:published", ATOM_NS) if entry.find("a:published", ATOM_NS) is not None else entry.find("published")
        title = title_el.text.strip() if title_el is not None and title_el.text else None
        url_ = link_el.get("href") if link_el is not None else None
        pub_date = pub_el.text if pub_el is not None else None
        if not title or not url_:
            continue
        records.append({
            "source_platform": "aggregated_writeup",
            "title": title,
            "url": url_,
            "authors": [],
            "programs": [],
            "bugs": [],
            "bounty": None,
            "publication_date": pub_date,
            "blog_source": name,
        })
    return records


def extract_title(html_bytes):
    page_html = html_bytes.decode("utf-8", errors="replace")
    m = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', page_html)
    if not m:
        m = re.search(r'<meta\s+content="([^"]*)"\s+property="og:title"', page_html)
    if m:
        title = m.group(1)
    else:
        m = re.search(r"<title>([^<]*)</title>", page_html)
        title = m.group(1) if m else None
    if not title:
        return None
    title = html.unescape(title)
    # strip a trailing " · Site Name" / " | Site Name" suffix if present
    title = re.split(r"\s*[·|]\s*[A-Z][\w ]*$", title)[0]
    return re.sub(r"\s+", " ", title).strip()


def collect_sitemap_blog(cfg):
    name, sitemap_url, include_re, max_pages = cfg["name"], cfg["sitemap"], cfg["include"], cfg["max_pages"]
    try:
        raw = fetch(sitemap_url, timeout=30)
    except Exception as e:
        print(f"sitemap fetch failed for {name}: {e}", file=sys.stderr)
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        print(f"sitemap parse failed for {name}: {e}", file=sys.stderr)
        return []

    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    pattern = re.compile(include_re)
    urls = []
    for url_el in root.findall("s:url", ns):
        loc = url_el.findtext("s:loc", namespaces=ns)
        lastmod = url_el.findtext("s:lastmod", namespaces=ns)
        if loc and pattern.search(loc):
            urls.append((loc, lastmod))

    records = []
    for loc, lastmod in urls[:max_pages]:
        try:
            html_bytes = fetch(loc, timeout=15)
        except Exception as e:
            print(f"page fetch failed for {loc}: {e}", file=sys.stderr)
            continue
        title = extract_title(html_bytes)
        if not title:
            continue
        records.append({
            "source_platform": "aggregated_writeup",
            "title": title,
            "url": loc,
            "authors": [],
            "programs": [],
            "bugs": [],
            "bounty": None,
            "publication_date": lastmod,
            "blog_source": name,
        })
        time.sleep(0.2)
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/raw/blogs.jsonl")
    args = ap.parse_args()

    total = 0
    with open(args.out, "w") as f:
        for name, url in ATOM_FEEDS:
            recs = collect_atom_feed(name, url)
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            total += len(recs)
            print(f"{name} (atom): {len(recs)} items", file=sys.stderr)

        for cfg in SITEMAP_BLOGS:
            recs = collect_sitemap_blog(cfg)
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            total += len(recs)
            print(f"{cfg['name']} (sitemap): {len(recs)} items", file=sys.stderr)

    print(f"Wrote {total} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
