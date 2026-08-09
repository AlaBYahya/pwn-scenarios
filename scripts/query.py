#!/usr/bin/env python3
"""Filter/search the dataset via the pre-built SQLite index (data/index.sqlite3).

Examples:
    python3 query.py --cwe CWE-89
    python3 query.py --playbook sqli --severity high
    python3 query.py --platform hackerone --confidence high --limit 5
    python3 query.py --search "cache poisoning"          # full-text search
    python3 query.py --cwe CWE-639 --json                # full record JSON out

Run without arguments to list available playbook_ids and platforms.
"""
import argparse
import json
import sqlite3
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="../data/index.sqlite3")
    ap.add_argument("--cwe", help="e.g. CWE-89")
    ap.add_argument("--severity", choices=["unknown", "low", "medium", "high", "critical"])
    ap.add_argument("--platform", choices=["hackerone", "aggregated_writeup", "ctf", "tryhackme", "other"])
    ap.add_argument("--playbook", help="playbook_id, e.g. idor, sqli, ssrf")
    ap.add_argument("--target-type", help="e.g. web, api, network")
    ap.add_argument("--confidence", choices=["high", "medium", "low"])
    ap.add_argument("--search", help="full-text search over title/class/tags/summary")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--json", action="store_true", help="print full record JSON instead of a one-line summary")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if args.search:
        sql = """
            SELECT s.* FROM scenarios s
            JOIN scenarios_fts fts ON s.id = fts.id
            WHERE scenarios_fts MATCH ?
        """
        params = [args.search]
        conditions, extra = [], []
        if args.cwe:
            conditions.append("s.cwe = ?"); extra.append(args.cwe)
        if args.severity:
            conditions.append("s.severity = ?"); extra.append(args.severity)
        if args.platform:
            conditions.append("s.platform = ?"); extra.append(args.platform)
        if args.playbook:
            conditions.append("s.playbook_id = ?"); extra.append(args.playbook)
        if args.target_type:
            conditions.append("s.target_type = ?"); extra.append(args.target_type)
        if args.confidence:
            conditions.append("s.confidence = ?"); extra.append(args.confidence)
        if conditions:
            sql += " AND " + " AND ".join(conditions)
            params += extra
        sql += " LIMIT ?"
        params.append(args.limit)
    else:
        conditions, params = [], []
        if args.cwe:
            conditions.append("cwe = ?"); params.append(args.cwe)
        if args.severity:
            conditions.append("severity = ?"); params.append(args.severity)
        if args.platform:
            conditions.append("platform = ?"); params.append(args.platform)
        if args.playbook:
            conditions.append("playbook_id = ?"); params.append(args.playbook)
        if args.target_type:
            conditions.append("target_type = ?"); params.append(args.target_type)
        if args.confidence:
            conditions.append("confidence = ?"); params.append(args.confidence)

        if not conditions:
            print("No filters given. Available playbook_ids:", file=sys.stderr)
            for row in cur.execute("SELECT playbook_id, COUNT(*) c FROM scenarios GROUP BY playbook_id ORDER BY c DESC"):
                print(f"  {row['c']:6d}  {row['playbook_id']}", file=sys.stderr)
            print("\nAvailable platforms:", file=sys.stderr)
            for row in cur.execute("SELECT platform, COUNT(*) c FROM scenarios GROUP BY platform ORDER BY c DESC"):
                print(f"  {row['c']:6d}  {row['platform']}", file=sys.stderr)
            sys.exit(0)

        sql = "SELECT * FROM scenarios WHERE " + " AND ".join(conditions) + " LIMIT ?"
        params.append(args.limit)

    rows = cur.execute(sql, params).fetchall()
    if not rows:
        print("No matching records.", file=sys.stderr)
        return

    for row in rows:
        if args.json:
            print(row["record_json"])
        else:
            print(f"{row['id']}  [{row['playbook_id']}]  {row['title']}  ({row['platform']}, {row['severity']})  {row['url']}")

    print(f"\n{len(rows)} record(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
