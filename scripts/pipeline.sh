#!/usr/bin/env bash
# End-to-end pipeline: collect raw data from all sources, normalize into the
# unified schema, validate, then build the searchable views (split-by-class +
# SQLite index).
#
# Usage: ./pipeline.sh [hackerone_pages] [pentesterland_limit] [ctf_per_page] [thm_repos_per_topic]
# Defaults below reproduce the full-scale run (~16.2k records): a complete
# HackerOne pull (260 pages x 50 = up to 13,000 disclosed reports) and a wide
# TryHackMe/CTF repo search. Pass smaller numbers for a quick local test run.
set -euo pipefail
cd "$(dirname "$0")"

H1_PAGES="${1:-260}"
PL_LIMIT="${2:-0}"
CTF_PER_PAGE="${3:-60}"
THM_REPOS_PER_TOPIC="${4:-50}"

mkdir -p ../data/raw ../data/scenarios

echo "== Collecting HackerOne (public metadata, ${H1_PAGES} pages) ==" >&2
python3 collect_hackerone.py --pages "$H1_PAGES" --out ../data/raw/hackerone.jsonl

echo "== Collecting Pentester Land curated writeup links ==" >&2
python3 collect_pentesterland.py --limit "$PL_LIMIT" --out ../data/raw/pentesterland.jsonl

echo "== Collecting additional curated GitHub writeup lists ==" >&2
python3 collect_curated_lists.py --out ../data/raw/curated_lists.jsonl

echo "== Collecting Medium publication RSS feeds ==" >&2
python3 collect_medium_feeds.py --out ../data/raw/medium_feeds.jsonl

echo "== Collecting CTF writeup repositories ==" >&2
python3 collect_ctf.py --per-page "$CTF_PER_PAGE" --out ../data/raw/ctf.jsonl

echo "== Collecting TryHackMe room writeups ==" >&2
python3 collect_tryhackme.py --repos-per-topic "$THM_REPOS_PER_TOPIC" --max-files-per-repo 400 --out ../data/raw/tryhackme.jsonl

if [ -s ../knowledge/community_submissions.jsonl ]; then
  echo "== Folding in community submissions ==" >&2
  cp ../knowledge/community_submissions.jsonl ../data/raw/community_submissions.jsonl
fi

echo "== Normalizing into unified schema ==" >&2
python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl

echo "== Validating ==" >&2
python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json

echo "== Building searchable views (by-class split + SQLite index) ==" >&2
python3 build_views.py --data ../data/scenarios/scenarios.jsonl --by-class-dir ../data/scenarios/by_class --db ../data/index.sqlite3

echo "== Building the attack decision graph ==" >&2
python3 build_graph.py --playbooks ../knowledge/vulnerability_playbooks.json --bridges ../knowledge/graph/bridges.json --tech-bridges ../knowledge/graph/technology_bridges.json --ai-bridges ../knowledge/graph/ai_bridges.json --out ../data/graph/attack_graph.json
python3 validate_graph.py --graph ../data/graph/attack_graph.json --schema ../schema/graph.schema.json

echo "== Building a class-balanced fine-tuning sample ==" >&2
python3 sample_balanced.py --data ../data/scenarios/scenarios.jsonl --max-per-class 20 --min-confidence medium --out ../data/scenarios/balanced_sample.jsonl

echo "== Sampling synthetic graph episodes ==" >&2
python3 simulate_graph.py --graph ../data/graph/attack_graph.json --episodes 3000 --policy random --out ../data/graph/episodes_random.jsonl
python3 simulate_graph.py --graph ../data/graph/attack_graph.json --episodes 1000 --policy greedy --out ../data/graph/episodes_greedy.jsonl
python3 simulate_graph.py --graph ../data/graph/attack_graph.json --episodes 1000 --policy epsilon_greedy --out ../data/graph/episodes_epsilon_greedy.jsonl

echo "Done. Canonical: ../data/scenarios/scenarios.jsonl | Browsable: ../data/scenarios/by_class/ | Queryable: ../data/index.sqlite3 | Graph: ../data/graph/attack_graph.json | Episodes: ../data/graph/episodes_*.jsonl" >&2
