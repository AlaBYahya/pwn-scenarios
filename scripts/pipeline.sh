#!/usr/bin/env bash
# End-to-end pipeline: collect raw data from all sources, normalize into the
# unified schema, validate, then build the searchable views (split-by-class +
# SQLite index).
#
# Usage: ./pipeline.sh [hackerone_pages] [pentesterland_limit] [ctf_per_page] [thm_repos_per_topic]
set -euo pipefail
cd "$(dirname "$0")"

H1_PAGES="${1:-10}"
PL_LIMIT="${2:-0}"
CTF_PER_PAGE="${3:-30}"
THM_REPOS_PER_TOPIC="${4:-20}"

mkdir -p ../data/raw ../data/scenarios

echo "== Collecting HackerOne (public metadata, ${H1_PAGES} pages) ==" >&2
python3 collect_hackerone.py --pages "$H1_PAGES" --out ../data/raw/hackerone.jsonl

echo "== Collecting Pentester Land curated writeup links ==" >&2
python3 collect_pentesterland.py --limit "$PL_LIMIT" --out ../data/raw/pentesterland.jsonl

echo "== Collecting CTF writeup repositories ==" >&2
python3 collect_ctf.py --per-page "$CTF_PER_PAGE" --out ../data/raw/ctf.jsonl

echo "== Collecting TryHackMe room writeups ==" >&2
python3 collect_tryhackme.py --repos-per-topic "$THM_REPOS_PER_TOPIC" --out ../data/raw/tryhackme.jsonl

echo "== Normalizing into unified schema ==" >&2
python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl

echo "== Validating ==" >&2
python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json

echo "== Building searchable views (by-class split + SQLite index) ==" >&2
python3 build_views.py --data ../data/scenarios/scenarios.jsonl --by-class-dir ../data/scenarios/by_class --db ../data/index.sqlite3

echo "Done. Canonical: ../data/scenarios/scenarios.jsonl | Browsable: ../data/scenarios/by_class/ | Queryable: ../data/index.sqlite3" >&2
