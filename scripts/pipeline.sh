#!/usr/bin/env bash
# End-to-end pipeline: collect raw data from all sources, normalize into the
# unified schema, then validate the result.
#
# Usage: ./pipeline.sh [hackerone_pages] [pentesterland_limit] [ctf_per_page]
set -euo pipefail
cd "$(dirname "$0")"

H1_PAGES="${1:-10}"
PL_LIMIT="${2:-0}"
CTF_PER_PAGE="${3:-30}"

mkdir -p ../data/raw ../data/scenarios

echo "== Collecting HackerOne (public metadata, ${H1_PAGES} pages) ==" >&2
python3 collect_hackerone.py --pages "$H1_PAGES" --out ../data/raw/hackerone.jsonl

echo "== Collecting Pentester Land curated writeup links ==" >&2
python3 collect_pentesterland.py --limit "$PL_LIMIT" --out ../data/raw/pentesterland.jsonl

echo "== Collecting CTF writeup repositories ==" >&2
python3 collect_ctf.py --per-page "$CTF_PER_PAGE" --out ../data/raw/ctf.jsonl

echo "== Normalizing into unified schema ==" >&2
python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl

echo "== Validating ==" >&2
python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json

echo "Done. Output: ../data/scenarios/scenarios.jsonl" >&2
