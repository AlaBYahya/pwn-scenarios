#!/usr/bin/env python3
"""Collect CTF writeup repository references via the public GitHub Search API.

We index repositories (not individual writeups) tagged with CTF-writeup-related
topics: title, description, URL, star count. Each becomes a `ctf` scenario record
grounded in the `ctf_challenge_generic` playbook -- a repository of real, disclosed
solve write-ups is itself a valid grounding instance for the general CTF-solving
process, without us needing to scrape and reproduce individual challenge writeups.

Usage:
    python3 collect_ctf.py --out ../data/raw/ctf.jsonl
    (uses `gh api` if available for auth'd higher rate limits, falls back to
    unauthenticated urllib otherwise)
"""
import argparse
import json
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

TOPICS = ["ctf-writeups", "ctf-writeup", "writeups"]
SEARCH_API = "https://api.github.com/search/repositories"


def search_via_gh(topic, per_page):
    out = subprocess.run(
        ["gh", "api", f"search/repositories?q=topic:{topic}&sort=stars&order=desc&per_page={per_page}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


def search_via_urllib(topic, per_page):
    q = urllib.parse.quote(f"topic:{topic}")
    url = f"{SEARCH_API}?q={q}&sort=stars&order=desc&per_page={per_page}"
    req = urllib.request.Request(url, headers={"user-agent": "pwn-scenarios-collector/1.0", "accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/raw/ctf.jsonl")
    ap.add_argument("--per-page", type=int, default=30)
    args = ap.parse_args()

    use_gh = shutil.which("gh") is not None
    seen = set()
    total = 0
    with open(args.out, "w") as f:
        for topic in TOPICS:
            try:
                result = search_via_gh(topic, args.per_page) if use_gh else search_via_urllib(topic, args.per_page)
            except Exception as e:
                print(f"search failed for topic={topic}: {e}", file=sys.stderr)
                continue
            for repo in result.get("items", []):
                url = repo["html_url"]
                if url in seen:
                    continue
                seen.add(url)
                record = {
                    "source_platform": "ctf",
                    "title": repo["full_name"],
                    "url": url,
                    "description": repo.get("description"),
                    "stars": repo.get("stargazers_count"),
                    "topic_matched": topic,
                }
                f.write(json.dumps(record) + "\n")
                total += 1

    print(f"Wrote {total} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
