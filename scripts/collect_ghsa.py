#!/usr/bin/env python3
"""Collect reviewed GitHub Security Advisories (GHSA) relevant to our vulnerability classes.

Unlike RSS/blog titles, each GHSA advisory ships an explicit CWE ID, so
normalize.py can classify these records by real CWE match instead of fragile
keyword matching against a headline -- much higher precision/grounding.

Queries the public /advisories REST API once per distinct CWE referenced by
knowledge/vulnerability_playbooks.json, deduplicating by ghsa_id across
queries (a single advisory can carry multiple CWEs). Requires a GitHub token
with basic read access (uses `gh api` via subprocess, so anything `gh auth
status` accepts works -- no extra scopes needed).

Usage:
    python3 collect_ghsa.py --playbooks ../knowledge/vulnerability_playbooks.json \
        --out ../data/raw/ghsa.jsonl --max-per-cwe 150
"""
import argparse
import json
import subprocess
import sys
import time


def load_target_cwes(playbooks_path):
    with open(playbooks_path) as f:
        playbooks = json.load(f)
    return sorted({p["cwe"] for p in playbooks if p.get("cwe")})


def fetch_page(cwe, page, per_page):
    # The API's ?cwes= filter takes the bare number (e.g. "79"), not "CWE-79" --
    # unlike every other field, which uses the full "CWE-79" form.
    cwe_number = cwe.split("-")[-1]
    # gh api handles auth + retries; --paginate is avoided so we can cap per-CWE.
    cmd = [
        "gh", "api",
        f"advisories?cwes={cwe_number}&type=reviewed&per_page={per_page}&page={page}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        print(f"  gh api error for {cwe} page {page}: {result.stderr.strip()}", file=sys.stderr)
        return None
    return json.loads(result.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--playbooks", default="../knowledge/vulnerability_playbooks.json")
    ap.add_argument("--out", default="../data/raw/ghsa.jsonl")
    ap.add_argument("--max-per-cwe", type=int, default=150)
    ap.add_argument("--per-page", type=int, default=100)
    ap.add_argument("--sleep", type=float, default=0.3)
    args = ap.parse_args()

    target_cwes = load_target_cwes(args.playbooks)
    print(f"Querying GHSA for {len(target_cwes)} distinct CWEs", file=sys.stderr)

    seen_ghsa_ids = set()
    total = 0
    with open(args.out, "w") as out_f:
        for cwe in target_cwes:
            fetched_for_cwe = 0
            page = 1
            # Fixed page size across the whole CWE, plus a hard page-count safety
            # cap -- shrinking per_page as the target is approached breaks the
            # page*per_page offset math and can loop forever if duplicate/withdrawn
            # records land near the cap on every page.
            max_pages = (args.max_per_cwe // args.per_page) + 3
            while fetched_for_cwe < args.max_per_cwe and page <= max_pages:
                body = fetch_page(cwe, page, args.per_page)
                if not body:
                    break
                if not isinstance(body, list) or not body:
                    break
                for adv in body:
                    ghsa_id = adv.get("ghsa_id")
                    if not ghsa_id or ghsa_id in seen_ghsa_ids or adv.get("withdrawn_at"):
                        continue
                    seen_ghsa_ids.add(ghsa_id)
                    vulns = adv.get("vulnerabilities") or []
                    first_vuln = vulns[0] if vulns else {}
                    ecosystem = (first_vuln.get("package") or {}).get("ecosystem")
                    package = (first_vuln.get("package") or {}).get("name")
                    cvss = ((adv.get("cvss_severities") or {}).get("cvss_v3") or {}).get("score")
                    record = {
                        "source_platform": "ghsa",
                        "ghsa_id": ghsa_id,
                        "cve_id": adv.get("cve_id"),
                        "title": adv.get("summary"),
                        "url": adv.get("html_url"),
                        "disclosed_at": adv.get("published_at"),
                        "severity": adv.get("severity"),
                        "cvss_score": cvss,
                        "cwe_ids": [c["cwe_id"] for c in (adv.get("cwes") or []) if c.get("cwe_id")],
                        "ecosystem": ecosystem,
                        "package": package,
                    }
                    out_f.write(json.dumps(record) + "\n")
                    total += 1
                    fetched_for_cwe += 1
                    if fetched_for_cwe >= args.max_per_cwe:
                        break
                print(f"  {cwe} page {page}: +{len(body)} raw, {fetched_for_cwe} kept so far", file=sys.stderr)
                if len(body) < args.per_page:
                    break
                page += 1
                time.sleep(args.sleep)

    print(f"Wrote {total} unique records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
