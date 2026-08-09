#!/usr/bin/env python3
"""Produce a class-balanced subset of the scenario dataset.

scenarios.jsonl repeats the same ~35 authored playbook texts across 7,342
records with different source metadata -- great for retrieval (look up "what
do I know about SSRF"), but a poor fit for supervised fine-tuning as-is: an
SFT run over the raw file would see the same canned scenario.process text
thousands of times with cosmetically different wrappers, which teaches
memorization of ~35 answers, not generalization. See the "Using this dataset"
section of the README before fine-tuning on this data directly.

If you want a bounded, diversity-balanced sample anyway (e.g. for a
demonstration, an eval set, or as *one* ingredient in a larger SFT mix), this
caps how many records any single vulnerability class can contribute and
prefers higher-confidence classification matches.

Usage:
    python3 sample_balanced.py --data ../data/scenarios/scenarios.jsonl \
        --max-per-class 20 --min-confidence medium --out ../data/scenarios/balanced_sample.jsonl
"""
import argparse
import json
from collections import defaultdict

CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/scenarios/scenarios.jsonl")
    ap.add_argument("--max-per-class", type=int, default=20)
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"], default="medium")
    ap.add_argument("--out", default="../data/scenarios/balanced_sample.jsonl")
    args = ap.parse_args()

    min_rank = CONFIDENCE_RANK[args.min_confidence]
    by_class = defaultdict(list)

    with open(args.data) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            conf = r["provenance"]["confidence"]
            if CONFIDENCE_RANK[conf] < min_rank:
                continue
            by_class[r["provenance"]["playbook_id"]].append(r)

    total = 0
    with open(args.out, "w") as out_f:
        for pb_id in sorted(by_class):
            records = by_class[pb_id]
            records.sort(key=lambda r: (-CONFIDENCE_RANK[r["provenance"]["confidence"]], r["id"]))
            for r in records[: args.max_per_class]:
                out_f.write(json.dumps(r, ensure_ascii=False) + "\n")
                total += 1

    print(f"Sampled {total} records across {len(by_class)} classes (max {args.max_per_class}/class, min confidence {args.min_confidence}) -> {args.out}")


if __name__ == "__main__":
    main()
