#!/usr/bin/env python3
"""Collect individual CTF challenge writeups from GitHub CTF-writeup repos.

Earlier version of this script indexed repositories, not writeups (one
record per repo). That badly undercounts: the `ctf-writeups` topic alone
spans 1,800+ repos, each often containing dozens of individual challenge
writeups. This version lists each repo's file tree and extracts one record
per challenge writeup file, the same file-level pattern as
collect_tryhackme.py/collect_hackthebox.py -- title/link only, never the
writeup body.

CTF repos use two layouts, both handled:
  - `Competition/ChallengeName.md` (flat -- the filename IS the title)
  - `Competition/ChallengeName/README.md` (nested -- the parent dir is the
    title; only used when the file itself is readme/index, unlike the HTB
    collector's author-prefixed-filename heuristic, which would misfire here)

Deduplication: same cross-repo normalized-title dedup as the other
per-file collectors, most-starred repo wins.

Usage:
    python3 collect_ctf.py --out ../data/raw/ctf.jsonl
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.parse

TOPICS = ["ctf-writeups", "ctf-writeup", "writeups"]

SKIP_FILENAMES = {
    "readme.md", "license.md", "contributing.md", "code_of_conduct.md",
    "learn.md", "instructions.md", "changelog.md", "security.md",
}
SKIP_PARENT_DIRS = {
    "write-ups", "writeups", "write_ups", "docs", "doc", "solutions", "src",
    "notes", "images", "img", "assets", "tools", "tool", "scripts", "misc",
    "files", "src", "exploit", "exploits", "solve", "solves",
}
SKIP_PATH_SEGMENTS = {"tools", "tool", "scripts", "assets", "images", "img", ".github", ".git"}
VALID_EXTENSIONS = (".md",)


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
    """Only prefer the parent directory for readme/index files -- unlike the
    HackTheBox collector, CTF repos commonly use flat `ChallengeName.md`
    files where the filename itself (not the parent dir) is the real title."""
    segments = path.split("/")
    filename = segments[-1]
    stem = filename.rsplit(".", 1)[0]
    if stem.lower() in ("readme", "index") and len(segments) >= 2:
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
    ap.add_argument("--out", default="../data/raw/ctf.jsonl")
    ap.add_argument("--repos-per-topic", type=int, default=40)
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
                        "source_platform": "ctf",
                        "title": title,
                        "url": blob_url,
                        "repo": repo_url,
                        "repo_stars": repo.get("stargazers_count"),
                    }
                    f.write(json.dumps(record) + "\n")
                    total += 1
                    if args.max_total and total >= args.max_total:
                        print(f"Wrote {total} records to {args.out} ({dup_titles_skipped} cross-repo duplicate titles skipped)", file=sys.stderr)
                        return

    print(f"Wrote {total} records to {args.out} ({dup_titles_skipped} cross-repo duplicate titles skipped)", file=sys.stderr)


if __name__ == "__main__":
    main()
