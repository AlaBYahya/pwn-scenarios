<p align="center"><img src="assets/logo.svg" alt="pwn-scenarios — IT sec for fun and profit" width="600"></p>

<p align="center">
  <a href="https://colab.research.google.com/github/AlaBYahya/pwn-scenarios/blob/main/notebooks/quickstart.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open in Colab"></a>
  <a href="https://github.com/AlaBYahya/pwn-scenarios/releases/latest"><img src="https://img.shields.io/github/v/release/AlaBYahya/pwn-scenarios" alt="Latest release"></a>
</p>

A dataset of penetration testing / bug bounty **scenarios** -- generalized,
reusable condition → step → impact → remediation processes for common
vulnerability classes, each grounded in a real, publicly disclosed report or
writeup -- plus an **attack decision graph** for chaining them, and the
scripts used to collect and produce both.

Built to be AI-ready: structured, schema-validated JSON Lines, suitable as
a RAG knowledge base, fine-tuning ingredient, or seed playbooks for an
autonomous pentesting/bug-bounty agent.

```json
{
  "vulnerability": {"class": "Insecure Direct Object Reference (IDOR)", "cwe": "CWE-639", "severity": "unknown"},
  "scenario": {
    "preconditions": ["Application exposes object identifiers ... ", "..."],
    "process": [
      {"step": 1, "action": "Map every endpoint that accepts an object identifier", "tools": ["Burp Suite"], "expected_observation": "..."},
      {"step": 2, "action": "...", "expected_observation": "..."}
    ],
    "impact": ["Unauthorized read access to other users' private data", "..."],
    "remediation": ["Enforce server-side ownership/authorization checks on every object access", "..."]
  },
  "source": {"platform": "hackerone", "url": "https://hackerone.com/reports/...", "program": "..."}
}
```

Full field reference: [`docs/SCHEMA.md`](docs/SCHEMA.md). Each record pairs
an originally-authored generic playbook (the reusable "how do you find/fix
this") with a real disclosed instance's metadata and a link back to it --
never the writeup's full text. See [`DATA_LICENSE`](DATA_LICENSE) for
exactly what is and isn't reproduced from original sources.

## The attack decision graph

[`data/graph/attack_graph.json`](data/graph/attack_graph.json) answers a
different question than the flat scenario list: **given what I've
established so far, what should I try next, and where might it lead** --
the same shape of reasoning a chess engine uses to evaluate candidate moves.

States are conditions/capabilities (`idor_confirmed`,
`low_priv_shell_obtained`, `full_host_compromise`); actions branch into
qualitatively-scored outcomes leading to new states. 35 generic
vulnerability classes, 17 real CVE chains (Log4Shell, Spring4Shell,
Zerologon, EternalBlue, PrintNightmare, MOVEit, and more -- CVE IDs/CVSS
verified against NVD), and 9 AI/LLM classes all converge through a shared
vocabulary of states, so e.g. a prompt injection that abuses an
over-scoped agent tool lands on the exact same `unauthorized_privileged_action_possible`
state that IDOR does.

```bash
cd scripts
python3 query_graph.py --from web_target_identified                                          # candidate first moves
python3 query_graph.py --best-path --from ssrf_confirmed --to full_cloud_account_compromise   # a strong path to a goal
```

`scripts/simulate_graph.py` samples synthetic (state, action, outcome,
reward) episodes from it for RL/behavior-cloning use -- a value-iteration
greedy policy reaches a `full_compromise` state 18.1% of the time vs 6.7%
for random. Full design, detection signals, and the simulator: [`docs/GRAPH.md`](docs/GRAPH.md).

## Dataset snapshot

**30,293 records** across **42 vulnerability classes**.

| Source | Platform | Records |
|---|---|---|
| HackerOne public Hacktivity (GraphQL API) | `hackerone` | 10,977 |
| GitHub CTF-writeup repos | `ctf` | 8,454 |
| Pentester Land + curated GitHub lists + RSS feeds + researcher blogs | `aggregated_writeup` | 6,106 |
| GitHub TryHackMe room-writeup repos | `tryhackme` | 2,956 |
| GitHub HackTheBox machine-writeup repos | `hackthebox` | 1,800 |

Records per vulnerability class (all 42; also in
[`knowledge/vulnerability_playbooks.json`](knowledge/vulnerability_playbooks.json)
or `python3 scripts/query.py` with no filters):

| Class | Records | | Class | Records |
|---|---:|---|---|---:|
| CTF challenge (general) | 8,250 | | Stored XSS | 184 |
| TryHackMe room (general) | 2,815 | | Insecure Deserialization | 182 |
| Reflected XSS | 2,650 | | Clickjacking | 176 |
| Sensitive Information Disclosure | 2,265 | | Subdomain Takeover | 152 |
| Broken Access Control | 1,919 | | Unrestricted File Upload | 132 |
| HackTheBox machine (general) | 1,770 | | Race Condition | 100 |
| Business Logic Flaw | 1,304 | | XXE | 94 |
| Authentication Bypass | 1,018 | | CORS Misconfiguration | 74 |
| Memory Corruption | 920 | | Prototype Pollution | 68 |
| Remote Code Execution | 793 | | Cache Poisoning | 66 |
| Denial of Service | 661 | | DOM XSS | 64 |
| CSRF | 598 | | OAuth Misconfiguration | 64 |
| IDOR | 598 | | Prompt Injection (AI/LLM) | 61 |
| Account Takeover | 509 | | GraphQL Abuse | 53 |
| SSRF | 506 | | 2FA Bypass | 51 |
| SQL Injection | 472 | | SSTI | 38 |
| Path Traversal | 413 | | JWT Vulnerabilities | 19 |
| Open Redirect | 407 | | Mass Assignment | 14 |
| Command Injection | 375 | | Hardcoded Secrets | 13 |
| HTTP Request Smuggling | 232 | | Training Data Poisoning (AI/LLM) | 1 |
| Cryptographic Issues | 211 | | Model Denial of Service (AI/LLM) | 1 |

54% of records are `confidence: "high"` classification matches (see
[`docs/SCHEMA.md`](docs/SCHEMA.md#confidence-levels)); the "general" rooms
above are thematically-named CTF/lab challenges that fell back to a generic
solving playbook rather than a specific vulnerability class.

## Using this dataset

`scenarios.jsonl` repeats a relatively small library of authored playbook
texts (48 classes) across 30k+ records with different source-metadata
wrappers. That's good for **retrieval** -- look up "what do I know about
SSRF," get back the playbook plus real grounding links. It's a poor fit for
**supervised fine-tuning as a raw dump**, since training on it directly
would mostly teach memorization of ~48 canned answers, not generalization.

- **RAG pipeline**: run `python3 scripts/build_views.py` once, then use
  `data/index.sqlite3` or `data/scenarios/by_class/` directly, keyed by
  CWE/class/tag.
- **Fine-tuning anyway** (e.g. one ingredient in a larger SFT mix, or an
  eval set): `scripts/sample_balanced.py` caps records per class and
  prefers higher-confidence matches:
  ```bash
  python3 scripts/sample_balanced.py --max-per-class 20 --min-confidence medium --out data/scenarios/balanced_sample.jsonl
  ```
- **Decision-making/RL data**: the [attack graph](#the-attack-decision-graph)
  and its simulator are the better starting point.

## Finding records

A single 30k-record JSONL file isn't practical to download/upload/browse
whole. It ships as fixed-size chunks instead:

1. **`data/scenarios/chunks/`** (committed, ~5MB per chunk +
   `manifest.json` with a SHA256 checksum) -- what you actually clone.
2. **`data/scenarios/scenarios.jsonl`** (gitignored, reassemble locally):
   ```bash
   cat data/scenarios/chunks/*.jsonl > data/scenarios/scenarios.jsonl
   ```
3. **`data/scenarios/by_class/<playbook_id>.jsonl`** and
   **`data/index.sqlite3`** (both gitignored, build locally with
   `python3 scripts/build_views.py`) -- per-class files and an indexed,
   full-text-searchable SQLite view.

Query the SQLite index directly, or via the bundled CLI:

```bash
cd scripts
python3 query.py --cwe CWE-89                          # by CWE
python3 query.py --playbook ssrf --severity high        # by class + severity
python3 query.py --search "cache poisoning"             # full-text search
python3 query.py                                        # no filters -> lists all playbook_ids/platforms
```

## Contributing a writeup

Anyone can submit a writeup link without touching JSON or the schema:
[open an issue using the "Submit a writeup" template](../../issues/new?template=submit-writeup.yml).
It asks for the URL, title, author, program, and vulnerability tags --
metadata only, same policy as every source in this dataset: we link to your
writeup, we don't copy it. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how
submissions get folded in, plus how to add a vulnerability class, a data
source, or a graph chain.

The dataset also grows on its own via scheduled collection:
[`daily-collect.yml`](.github/workflows/daily-collect.yml) (RSS feeds +
blogs) and [`weekly-collect.yml`](.github/workflows/weekly-collect.yml)
(the full pipeline) run automatically and commit new records.

## Regenerating locally

```bash
pip install -r requirements.txt
cd scripts
./pipeline.sh          # full run (~20 min): every collector -> normalize -> validate -> views -> graph -> chunks
./pipeline.sh 10 0 20 10   # smaller numbers for a quick local test
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for extending the dataset (new
vulnerability classes, data sources, or graph chains) and
[`docs/GRAPH.md`](docs/GRAPH.md) / [`docs/SCHEMA.md`](docs/SCHEMA.md) for
full field and design references. Engineering history (what changed each
round, sources evaluated and rejected, and why) lives in
[`CHANGELOG.md`](CHANGELOG.md).

## Repo layout

```
schema/                            JSON Schemas for scenario records and the attack graph
knowledge/vulnerability_playbooks.json   Authored playbooks (the "process" library)
knowledge/graph/                   Authored graph chaining logic (generic, technology/CVE, AI/LLM bridges)
knowledge/community_submissions.jsonl    Committed log of writeups submitted via the issue template
scripts/collect_*.py               One collector per source (see CONTRIBUTING.md)
scripts/normalize.py               Classifies raw records against playbooks, emits unified schema
scripts/validate.py / validate_graph.py   Schema + integrity validation
scripts/build_views.py             Builds by_class/ split and the SQLite index
scripts/build_graph.py             Generates the attack graph from playbooks + bridge files
scripts/query.py / query_graph.py  CLIs for filtering the dataset / traversing the graph
scripts/simulate_graph.py          Samples synthetic RL episodes from the graph
scripts/chunk_scenarios.py         Splits scenarios.jsonl into git-friendly chunks
scripts/sample_balanced.py         Class-balanced subset for fine-tuning use
scripts/ingest_submissions.py      Converts an issue-form submission into community_submissions.jsonl
scripts/pipeline.sh                Runs the full chain end to end
data/scenarios/chunks/             The committed dataset
data/graph/attack_graph.json       The generated attack decision graph
data/graph/episodes_*.jsonl        Simulated episodes per policy
docs/SCHEMA.md, docs/GRAPH.md      Field and design references
```

## Known limitations

- `scenario.process` is a generic playbook per vulnerability class, not a
  transcription of that specific instance's actual steps -- a deliberate
  trade-off for legal safety and automation at scale (see
  [`DATA_LICENSE`](DATA_LICENSE)), not a bug.
- Severity is `"unknown"` for most records -- most sources don't expose it
  publicly.
- Classification is keyword/alias-based, not semantic; filter on
  `provenance.confidence` if you need precision.
- 6 of the 9 AI/LLM classes have zero real grounded instances yet (only
  `prompt_injection`, `model_denial_of_service`, and
  `training_data_poisoning` matched anything so far) -- the playbooks and
  graph chains are ready as soon as more real writeups use this
  terminology.

## License

Code (`scripts/`, `schema/`): [MIT](LICENSE).
Data (`data/`, `knowledge/`): [CC BY 4.0](DATA_LICENSE).
