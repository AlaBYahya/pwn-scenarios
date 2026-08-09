#!/usr/bin/env python3
"""Collect HackTheBox machine-writeup references from GitHub.

Same pattern as collect_tryhackme.py: HTB writeup repos overwhelmingly
follow a `challenges/Category/BoxName/author-writeup.ext` or
`BoxName/writeup.ext` layout where the parent directory is the box/challenge
name. Unlike TryHackMe repos, HTB writeup repos commonly use PDF files
alongside (or instead of) markdown, so both extensions are collected --
still title/link only, never the file content.

Deduplication: identical to collect_tryhackme.py -- many repos independently
write up the same popular box (e.g. "Blue", "Legacy"), so we keep only the
first occurrence of each normalized box title, most-starred repo first.

Usage:
    python3 collect_hackthebox.py --out ../data/raw/hackthebox.jsonl
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.parse

TOPICS = ["hackthebox-writeups", "htb-writeups", "hackthebox-writeup"]

SKIP_FILENAMES = {
    "readme.md", "license.md", "contributing.md", "code_of_conduct.md",
    "learn.md", "instructions.md", "changelog.md", "security.md",
}
SKIP_PARENT_DIRS = {
    "write-ups", "writeups", "write_ups", "box", "boxes", "machine", "machines",
    "challenges", "challenge", "docs", "doc", "solutions", "ctf", "src", "notes",
    "images", "img", "assets", "tools", "tool", "scripts", "misc", "pwn", "web",
    "crypto", "forensics", "reversing", "misc-1", "osint", "hardware",
}
SKIP_PATH_SEGMENTS = {"tools", "tool", "scripts", "assets", "images", "img", ".github", ".git"}
VALID_EXTENSIONS = (".md", ".pdf")


def gh_json(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return json.loads(out.stdout)


def search_repos(topic, per_page):
    return gh_json(f"search/repositories?q=topic:{topic}&sort=stars&order=desc&per_page={per_page}")


def list_writeup_files(owner, repo, branch, max_files):
    tree = gh_json(f"repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    files = []
    for node in tree.get("tree", []):
        if node.get("type") != "blob":
            continue
        path = node["path"]
        if not path.lower().endswith(VALID_EXTENSIONS):
            continue
        segments = path.split("/")
        if any(seg.lower() in SKIP_PATH_SEGMENTS for seg in segments[:-1]):
            continue
        filename = segments[-1].lower()
        if filename in SKIP_FILENAMES:
            if len(segments) < 2 or segments[-2].lower().replace(" ", "").replace("-", "").replace("_", "") in {s.replace(" ", "") for s in SKIP_PARENT_DIRS}:
                continue
        files.append(path)
        if len(files) >= max_files:
            break
    return files


def title_from_path(path):
    segments = path.split("/")
    filename = segments[-1]
    stem = filename.rsplit(".", 1)[0]
    if stem.lower() in ("readme", "index") and len(segments) >= 2:
        raw = segments[-2]
    elif len(segments) >= 2 and segments[-2].lower().replace(" ", "").replace("-", "").replace("_", "") not in {s.replace(" ", "") for s in SKIP_PARENT_DIRS}:
        # for author-named writeup files (e.g. "Qarnix-Breach.pdf"), prefer the parent dir name
        raw = segments[-2]
    else:
        raw = stem
    raw = raw.replace("-", " ").replace("_", " ")
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw


def normalize_title(title):
    return re.sub(r"[^a-z0-9]", "", title.lower())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/raw/hackthebox.jsonl")
    ap.add_argument("--repos-per-topic", type=int, default=30)
    ap.add_argument("--max-files-per-repo", type=int, default=300)
    ap.add_argument("--max-total", type=int, default=0, help="0 = no cap")
    args = ap.parse_args()

    seen_repo_urls = set()
    seen_titles = set()
    total = 0
    dup_titles_skipped = 0

    with open(args.out, "w") as f:
        for topic in TOPICS:
            try:
                result = search_repos(topic, args.repos_per_topic)
            except Exception as e:
                print(f"search failed for topic={topic}: {e}", file=sys.stderr)
                continue

            for repo in result.get("items", []):
                repo_url = repo["html_url"]
                if repo_url in seen_repo_urls:
                    continue
                seen_repo_urls.add(repo_url)
                owner = repo["owner"]["login"]
                name = repo["name"]
                branch = repo.get("default_branch") or "main"

                try:
                    files = list_writeup_files(owner, name, branch, args.max_files_per_repo)
                except Exception as e:
                    print(f"tree fetch failed for {repo_url}: {e}", file=sys.stderr)
                    continue

                for path in files:
                    title = title_from_path(path)
                    norm = normalize_title(title)
                    if not norm or title.strip().isdigit():
                        continue
                    if norm in seen_titles:
                        dup_titles_skipped += 1
                        continue
                    seen_titles.add(norm)

                    blob_url = f"https://github.com/{owner}/{name}/blob/{branch}/{urllib.parse.quote(path)}"
                    record = {
                        "source_platform": "hackthebox",
                        "title": title,
                        "url": blob_url,
                        "repo": repo_url,
                        "repo_stars": repo.get("stargazers_count"),
                    }
                    f.write(json.dumps(record) + "\n")
                    total += 1
                    if args.max_total and total >= args.max_total:
                        print(f"Wrote {total} records to {args.out} ({dup_titles_skipped} cross-repo duplicate box titles skipped)", file=sys.stderr)
                        return

    print(f"Wrote {total} records to {args.out} ({dup_titles_skipped} cross-repo duplicate box titles skipped)", file=sys.stderr)


if __name__ == "__main__":
    main()
