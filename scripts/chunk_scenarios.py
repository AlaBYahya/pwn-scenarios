#!/usr/bin/env python3
"""Split scenarios.jsonl into fixed-size chunks for comfortable download/upload/reading.

scenarios.jsonl itself is the canonical source of truth and isn't derived
from anything else the way by_class/index.sqlite3 are (it's the actual
normalized output of the collection pipeline), so it can't just be
gitignored and regenerated on demand the way those were -- it has to be
shipped somehow. A single 78MB+ file is exactly the kind of thing this
project has already had to walk back once (see the by_class/SQLite fix).
The fix here is the same idea applied differently: split the one big file
into a directory of small, fixed-size, sequentially-numbered chunks.

Chunks are the thing committed to git; scenarios.jsonl itself is treated as
a local working file (gitignored, like data/raw/) that downstream scripts
(build_views.py, sample_balanced.py, build_graph.py's dependents) read from.
Reassemble it from chunks with:

    cat data/scenarios/chunks/*.jsonl > data/scenarios/scenarios.jsonl

Usage:
    python3 chunk_scenarios.py --data ../data/scenarios/scenarios.jsonl \
        --out-dir ../data/scenarios/chunks --records-per-chunk 2000
"""
import argparse
import hashlib
import json
import os
import shutil


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/scenarios/scenarios.jsonl")
    ap.add_argument("--out-dir", default="../data/scenarios/chunks")
    ap.add_argument("--records-per-chunk", type=int, default=2000)
    args = ap.parse_args()

    if os.path.isdir(args.out_dir):
        shutil.rmtree(args.out_dir)
    os.makedirs(args.out_dir, exist_ok=True)

    with open(args.data) as f:
        lines = [line for line in f if line.strip()]

    total = len(lines)
    n_chunks = (total + args.records_per_chunk - 1) // args.records_per_chunk
    width = max(3, len(str(n_chunks)))

    manifest = {
        "total_records": total,
        "records_per_chunk": args.records_per_chunk,
        "chunk_count": n_chunks,
        "sha256": hashlib.sha256("".join(lines).encode()).hexdigest(),
        "chunks": [],
    }

    for i in range(n_chunks):
        chunk_lines = lines[i * args.records_per_chunk: (i + 1) * args.records_per_chunk]
        name = f"scenarios.part{str(i + 1).zfill(width)}.jsonl"
        path = os.path.join(args.out_dir, name)
        with open(path, "w") as f:
            f.writelines(chunk_lines)
        manifest["chunks"].append({
            "file": name,
            "records": len(chunk_lines),
            "bytes": os.path.getsize(path),
        })

    with open(os.path.join(args.out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    sizes = [c["bytes"] for c in manifest["chunks"]]
    avg_mb = (sum(sizes) / len(sizes) / 1024 / 1024) if sizes else 0
    print(f"Split {total} records into {n_chunks} chunks (~{avg_mb:.1f}MB avg) in {args.out_dir}")


if __name__ == "__main__":
    main()
