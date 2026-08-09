#!/usr/bin/env python3
"""Ingest a community writeup submission into knowledge/community_submissions.jsonl.

Unlike data/raw/*.jsonl (ephemeral, re-fetchable from a live API/feed and
gitignored), community submissions are NOT reproducible by re-running a
collector -- they're real human contributions -- so they live under
knowledge/ and are committed to the repo directly.

Two ways to use it:

  1. From a GitHub issue opened via the "Submit a writeup" issue form:
         python3 ingest_submissions.py --from-issue 42

  2. Manually:
         python3 ingest_submissions.py --url https://... --title "..." \
             --author "..." --program "..." --tags "IDOR,SSRF" --bounty "$500" --date 2026-08-09

After ingesting, re-run the normalizer to fold new submissions into the
published dataset:
    cp ../knowledge/community_submissions.jsonl ../data/raw/community_submissions.jsonl
    python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl
    python3 validate.py && python3 build_views.py
"""
import argparse
import json
import re
import subprocess
import sys

STORE_PATH_DEFAULT = "../knowledge/community_submissions.jsonl"


def parse_issue_body(body):
    """Parse a GitHub issue-form body (### Label\\n\\nvalue\\n\\n### Label2...) into a dict."""
    fields = {}
    sections = re.split(r"^###\s+", body, flags=re.MULTILINE)[1:]
    for section in sections:
        lines = section.strip().splitlines()
        if not lines:
            continue
        label = lines[0].strip().lower()
        value = "\n".join(lines[1:]).strip()
        if value.lower() in ("_no response_", ""):
            value = None
        fields[label] = value
    return fields


def field_like(fields, *keywords):
    for label, value in fields.items():
        if all(k in label for k in keywords):
            return value
    return None


def from_issue(issue_number):
    out = subprocess.run(
        ["gh", "issue", "view", str(issue_number), "--json", "title,body,author,url"],
        capture_output=True, text=True, check=True,
    )
    issue = json.loads(out.stdout)
    fields = parse_issue_body(issue["body"])

    url = field_like(fields, "url")
    title = field_like(fields, "title") or issue["title"]
    author = field_like(fields, "author")
    program = field_like(fields, "program")
    tags_raw = field_like(fields, "tag")
    bounty = field_like(fields, "bounty")
    date = field_like(fields, "date")

    if not url:
        print(f"issue #{issue_number}: no URL field found, skipping", file=sys.stderr)
        return None

    return build_record(url, title, author, program, tags_raw, bounty, date,
                         submitted_by=issue.get("author", {}).get("login"))


def build_record(url, title, author, program, tags_raw, bounty, date, submitted_by=None):
    tags = [t.strip() for t in (tags_raw or "").split(",") if t.strip()]
    return {
        "source_platform": "aggregated_writeup",
        "title": title,
        "url": url,
        "authors": [author] if author else [],
        "programs": [program] if program else [],
        "bugs": tags,
        "bounty": bounty,
        "publication_date": date,
        "submitted_by": submitted_by,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=STORE_PATH_DEFAULT)
    ap.add_argument("--from-issue", type=int, help="GitHub issue number opened via the writeup submission form")
    ap.add_argument("--url")
    ap.add_argument("--title")
    ap.add_argument("--author")
    ap.add_argument("--program")
    ap.add_argument("--tags", help="comma-separated")
    ap.add_argument("--bounty")
    ap.add_argument("--date")
    args = ap.parse_args()

    if args.from_issue:
        record = from_issue(args.from_issue)
    elif args.url and args.title:
        record = build_record(args.url, args.title, args.author, args.program, args.tags, args.bounty, args.date)
    else:
        print("Provide either --from-issue N, or at least --url and --title.", file=sys.stderr)
        sys.exit(2)

    if not record:
        sys.exit(1)

    try:
        with open(args.store) as f:
            existing_urls = {json.loads(line)["url"] for line in f if line.strip()}
    except FileNotFoundError:
        existing_urls = set()

    if record["url"] in existing_urls:
        print(f"Already have a submission for {record['url']}, skipping.", file=sys.stderr)
        sys.exit(0)

    with open(args.store, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Ingested: {record['title']} ({record['url']}) -> {args.store}", file=sys.stderr)


if __name__ == "__main__":
    main()
