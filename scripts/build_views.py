#!/usr/bin/env python3
"""Build searchable/filterable "views" on top of the canonical dataset.

data/scenarios/scenarios.jsonl is the source of truth (one JSON object per
line -- easy to diff in git, directly loadable by tools like the HuggingFace
`datasets` library). A single 6MB+ JSONL file is not practical to browse or
filter by hand, so this script derives two views from it:

  1. data/scenarios/by_class/<playbook_id>.jsonl
     The same records, split per vulnerability class, for browsing a single
     class on GitHub without downloading everything.

  2. data/index.sqlite3
     A SQLite database with indexed columns (cwe, severity, platform,
     playbook_id, target_type, confidence) plus an FTS5 full-text index over
     title/summary/tags, for actual query filtering. See scripts/query.py.

Usage:
    python3 build_views.py --data ../data/scenarios/scenarios.jsonl
"""
import argparse
import json
import os
import shutil
import sqlite3


def build_by_class(records, out_dir):
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    buckets = {}
    for r in records:
        pb_id = r["provenance"]["playbook_id"]
        buckets.setdefault(pb_id, []).append(r)

    for pb_id, recs in buckets.items():
        path = os.path.join(out_dir, f"{pb_id}.jsonl")
        with open(path, "w") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return buckets


def build_sqlite(records, db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE scenarios (
            id TEXT PRIMARY KEY,
            title TEXT,
            vulnerability_class TEXT,
            cwe TEXT,
            owasp_category TEXT,
            severity TEXT,
            target_type TEXT,
            playbook_id TEXT,
            confidence TEXT,
            platform TEXT,
            program TEXT,
            author TEXT,
            disclosed_at TEXT,
            url TEXT,
            tags TEXT,
            record_json TEXT
        )
    """)
    cur.execute("CREATE INDEX idx_cwe ON scenarios(cwe)")
    cur.execute("CREATE INDEX idx_severity ON scenarios(severity)")
    cur.execute("CREATE INDEX idx_platform ON scenarios(platform)")
    cur.execute("CREATE INDEX idx_playbook ON scenarios(playbook_id)")
    cur.execute("CREATE INDEX idx_target_type ON scenarios(target_type)")
    cur.execute("CREATE INDEX idx_confidence ON scenarios(confidence)")

    cur.execute("""
        CREATE VIRTUAL TABLE scenarios_fts USING fts5(
            id UNINDEXED, title, vulnerability_class, tags, summary
        )
    """)

    for r in records:
        tags = ", ".join(r.get("tags", []))
        cur.execute(
            """INSERT INTO scenarios VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                r["id"],
                r["title"],
                r["vulnerability"]["class"],
                r["vulnerability"]["cwe"],
                r["vulnerability"]["owasp_category"],
                r["vulnerability"]["severity"],
                r["target"]["type"],
                r["provenance"]["playbook_id"],
                r["provenance"]["confidence"],
                r["source"]["platform"],
                r["source"].get("program"),
                r["source"].get("author"),
                r["source"].get("disclosed_at"),
                r["source"]["url"],
                tags,
                json.dumps(r, ensure_ascii=False),
            ),
        )
        cur.execute(
            "INSERT INTO scenarios_fts (id, title, vulnerability_class, tags, summary) VALUES (?,?,?,?,?)",
            (r["id"], r["title"], r["vulnerability"]["class"], tags, r["scenario"]["summary"]),
        )

    conn.commit()
    conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/scenarios/scenarios.jsonl")
    ap.add_argument("--by-class-dir", default="../data/scenarios/by_class")
    ap.add_argument("--db", default="../data/index.sqlite3")
    args = ap.parse_args()

    with open(args.data) as f:
        records = [json.loads(line) for line in f if line.strip()]

    buckets = build_by_class(records, args.by_class_dir)
    build_sqlite(records, args.db)

    print(f"Split {len(records)} records into {len(buckets)} by-class files under {args.by_class_dir}")
    print(f"Built SQLite index at {args.db}")


if __name__ == "__main__":
    main()
