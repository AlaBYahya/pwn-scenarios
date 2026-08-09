#!/usr/bin/env python3
"""Collect public, disclosed HackerOne report metadata via HackerOne's public GraphQL API.

Only fields visible to an unauthenticated caller are requested (title, weakness,
severity, program, disclosure date, URL). Full report bodies (vulnerability_information,
impact) require authentication and are intentionally NOT fetched -- this dataset stores
normalized classification data plus a link back to the source, not writeup text.

Usage:
    python3 collect_hackerone.py --pages 20 --out ../data/raw/hackerone.jsonl
"""
import argparse
import json
import sys
import time
import urllib.request

GRAPHQL_URL = "https://hackerone.com/graphql"

QUERY = """
query($first: Int, $after: String, $where: FiltersReportFilterInput) {
  reports(first: $first, after: $after, where: $where) {
    pageInfo { endCursor hasNextPage }
    nodes {
      _id
      title
      url
      disclosed_at
      severity { rating }
      weakness { name }
      team { name handle }
    }
  }
}
"""


def fetch_page(after, page_size):
    payload = {
        "query": QUERY,
        "variables": {
            "first": page_size,
            "after": after,
            "where": {"disclosed_at": {"_neq": None}},
        },
    }
    req = urllib.request.Request(
        GRAPHQL_URL,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "user-agent": "pwn-scenarios-collector/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=10, help="number of pages to fetch")
    ap.add_argument("--page-size", type=int, default=50)
    ap.add_argument("--out", default="../data/raw/hackerone.jsonl")
    ap.add_argument("--sleep", type=float, default=0.5, help="seconds between requests")
    args = ap.parse_args()

    after = None
    total = 0
    with open(args.out, "w") as f:
        for page in range(args.pages):
            body = fetch_page(after, args.page_size)
            if "errors" in body:
                print(f"GraphQL error on page {page}: {body['errors']}", file=sys.stderr)
                break
            conn = body["data"]["reports"]
            for node in conn["nodes"]:
                record = {
                    "source_platform": "hackerone",
                    "report_id": node["_id"],
                    "title": node["title"],
                    "url": node["url"],
                    "disclosed_at": node["disclosed_at"],
                    "severity": (node.get("severity") or {}).get("rating"),
                    "weakness": (node.get("weakness") or {}).get("name"),
                    "program": (node.get("team") or {}).get("name"),
                    "program_handle": (node.get("team") or {}).get("handle"),
                }
                f.write(json.dumps(record) + "\n")
                total += 1
            page_info = conn["pageInfo"]
            print(f"page {page + 1}/{args.pages}: fetched {len(conn['nodes'])} reports (total {total})", file=sys.stderr)
            if not page_info["hasNextPage"]:
                break
            after = page_info["endCursor"]
            time.sleep(args.sleep)

    print(f"Wrote {total} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
