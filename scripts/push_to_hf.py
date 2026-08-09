#!/usr/bin/env python3
"""Sync the dataset to the Hugging Face Hub mirror (aeby/pwn-scenarios).

Converts scenarios.jsonl to Parquet (the raw JSONL trips up `datasets`'
schema inference: columns that are all-null in the first chunk it samples --
e.g. source.bounty -- fail to cast once a later chunk has a real string),
regenerates the dataset card with record counts computed from the data
itself rather than hardcoded, and pushes the attack graph + episodes too.

Requires HF_TOKEN in the environment (a write-scoped token from
https://huggingface.co/settings/tokens). Never hardcode it -- it's stored as
a GitHub Actions secret and passed in via env: in the workflow.

Usage:
    export HF_TOKEN=...
    python3 push_to_hf.py --data ../data/scenarios/scenarios.jsonl --repo-id aeby/pwn-scenarios
"""
import argparse
import json
import os
import sys
from collections import Counter

import pyarrow.json as paj
import pyarrow.parquet as pq
from huggingface_hub import HfApi

CARD_TEMPLATE = """---
license: cc-by-4.0
task_categories:
- text-generation
- question-answering
language:
- en
tags:
- security
- cybersecurity
- pentesting
- bug-bounty
- cve
- rag
- llm-security
pretty_name: pwn-scenarios
size_categories:
- 10K<n<100K
---

<p align="center"><img src="https://raw.githubusercontent.com/AlaBYahya/pwn-scenarios/main/assets/logo.svg" alt="pwn-scenarios — IT sec for fun and profit" width="600"></p>

# pwn-scenarios

**{total} records, {num_classes} vulnerability classes.** A dataset of penetration testing / bug bounty **scenarios** -- generalized, reusable condition → step → impact → remediation playbooks for common vulnerability classes, each grounded in a real, publicly disclosed report or writeup.

Full source, collection scripts, the companion attack decision graph, and complete docs live on GitHub: **https://github.com/AlaBYahya/pwn-scenarios**

## Example record

```json
{{
  "vulnerability": {{"class": "Insecure Direct Object Reference (IDOR)", "cwe": "CWE-639", "severity": "unknown"}},
  "scenario": {{
    "preconditions": ["Application exposes object identifiers ...", "..."],
    "process": [
      {{"step": 1, "action": "Map every endpoint that accepts an object identifier", "tools": ["Burp Suite"], "expected_observation": "..."}},
      {{"step": 2, "action": "...", "expected_observation": "..."}}
    ],
    "impact": ["Unauthorized read access to other users' private data", "..."],
    "remediation": ["Enforce server-side ownership/authorization checks on every object access", "..."]
  }},
  "source": {{"platform": "hackerone", "url": "https://hackerone.com/reports/...", "program": "..."}}
}}
```

## Loading

```python
from datasets import load_dataset
ds = load_dataset("{repo_id}")
```

## Sources

| Platform | Records |
|---|---:|
{platform_table}

Each record pairs an originally-authored generic playbook with a real disclosed instance's *metadata* (title, URL, date, author) -- never the writeup's full text. See the GitHub repo's `DATA_LICENSE` for exactly what is and isn't reproduced from original sources.

## The attack decision graph

`graph/attack_graph.json` (included in this repo) models pentesting as a chess engine evaluates moves: {num_states} states, {num_actions} actions, including 17 real CVE chains (Log4Shell, Spring4Shell, Zerologon, EternalBlue, MOVEit, and more) verified against NVD. `graph/episodes_*.jsonl` are synthetic (state, action, outcome, reward) rollouts sampled from it under random / greedy / epsilon-greedy policies, suitable for RL or behavior-cloning experiments. Full design: see `docs/GRAPH.md` on GitHub.

## Using this dataset

This is retrieval/RAG material more than a raw fine-tuning dump -- a relatively small library of playbook texts repeats across {total} records with different source-metadata wrappers, so training on it directly mostly teaches memorization of the canned answers rather than generalization. Good uses:

- **RAG**: index by `vulnerability.cwe` / `vulnerability.class` / `source.platform`, retrieve the matching playbook for a given vulnerability class.
- **Balanced fine-tuning subset**: the GitHub repo's `scripts/sample_balanced.py` caps records per class and filters by classification confidence.
- **RL / decision-making data**: the attack graph and its episode files.

## License

Data: [CC BY 4.0](https://github.com/AlaBYahya/pwn-scenarios/blob/main/DATA_LICENSE). Code (collection/generation scripts): [MIT](https://github.com/AlaBYahya/pwn-scenarios/blob/main/LICENSE), on GitHub.

## Citation

See [CITATION.cff](https://github.com/AlaBYahya/pwn-scenarios/blob/main/CITATION.cff) on GitHub.

*Auto-synced from GitHub -- last updated by the weekly collection workflow.*
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/scenarios/scenarios.jsonl")
    ap.add_argument("--graph", default="../data/graph/attack_graph.json")
    ap.add_argument("--episodes-dir", default="../data/graph")
    ap.add_argument("--repo-id", default="aeby/pwn-scenarios")
    ap.add_argument("--parquet-tmp", default="/tmp/pwn-scenarios-train.parquet")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        print("HF_TOKEN not set in the environment -- skipping HF sync.", file=sys.stderr)
        sys.exit(0)

    platform_counts = Counter()
    playbook_ids = set()
    total = 0
    with open(args.data) as f:
        for line in f:
            r = json.loads(line)
            platform_counts[r["source"]["platform"]] += 1
            playbook_ids.add(r["provenance"]["playbook_id"])
            total += 1
    num_classes = len(playbook_ids)

    with open(args.graph) as f:
        graph = json.load(f)
    num_states, num_actions = len(graph["states"]), len(graph["actions"])

    platform_table = "\n".join(
        f"| `{p}` | {c:,} |" for p, c in platform_counts.most_common()
    )

    card = CARD_TEMPLATE.format(
        total=f"{total:,}",
        num_classes=num_classes,
        repo_id=args.repo_id,
        platform_table=platform_table,
        num_states=num_states,
        num_actions=num_actions,
    )

    table = paj.read_json(args.data, read_options=paj.ReadOptions(block_size=200 * 1024 * 1024))
    pq.write_table(table, args.parquet_tmp)

    api = HfApi(token=token)
    api.upload_file(path_or_fileobj=args.parquet_tmp, path_in_repo="data/train.parquet", repo_id=args.repo_id, repo_type="dataset", commit_message=f"Sync: {total} records")
    api.upload_file(path_or_fileobj=args.graph, path_in_repo="graph/attack_graph.json", repo_id=args.repo_id, repo_type="dataset", commit_message="Sync attack graph")
    for name in ("episodes_random.jsonl", "episodes_greedy.jsonl", "episodes_epsilon_greedy.jsonl"):
        path = os.path.join(args.episodes_dir, name)
        if os.path.exists(path):
            api.upload_file(path_or_fileobj=path, path_in_repo=f"graph/{name}", repo_id=args.repo_id, repo_type="dataset", commit_message=f"Sync {name}")

    from io import BytesIO
    api.upload_file(path_or_fileobj=BytesIO(card.encode("utf-8")), path_in_repo="README.md", repo_id=args.repo_id, repo_type="dataset", commit_message="Sync dataset card")

    os.remove(args.parquet_tmp)
    print(f"Synced {total} records ({num_classes} classes) to https://huggingface.co/datasets/{args.repo_id}", file=sys.stderr)


if __name__ == "__main__":
    main()
