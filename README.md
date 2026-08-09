# pwn-scenarios

A dataset of penetration testing / bug bounty **scenarios** -- generalized,
reusable condition → step → impact → remediation processes for common
vulnerability classes, each grounded in a real, publicly disclosed report or
writeup -- plus the scripts used to collect and produce it.

Built to be AI-ready: structured, schema-validated JSON Lines, suitable as
fine-tuning/instruction data, a RAG knowledge base, or seed playbooks for an
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

Full field reference: [`docs/SCHEMA.md`](docs/SCHEMA.md).

## Beyond a flat list: the attack decision graph

The scenario dataset above answers "how do I find/fix vulnerability class X."
[`data/graph/attack_graph.json`](data/graph/attack_graph.json) answers a
different question: **given what I've established so far, what should I try
next, and where might it lead** -- the same shape of reasoning a chess engine
uses to evaluate candidate moves and their resulting positions.

States are conditions/capabilities ("`idor_confirmed`",
"`low_priv_shell_obtained`", "`full_host_compromise`"); actions are moves
that branch into qualitatively-scored outcomes leading to new states. 35
vulnerability classes converge and chain through a shared vocabulary of 15
hand-authored bridge states -- e.g. six different RCE-capable classes all
converge on `low_priv_shell_obtained`, and SSRF can chain into
`cloud_metadata_reachable -> cloud_credentials_obtained -> full_cloud_account_compromise`.

```bash
cd scripts
python3 query_graph.py --from web_target_identified                                    # candidate first moves
python3 query_graph.py --best-path --from ssrf_confirmed --to full_cloud_account_compromise   # a strong path to a goal
```

Full design + more examples: [`docs/GRAPH.md`](docs/GRAPH.md).

## Why the scenario dataset has this shape

Bug bounty writeups typically show the *destination* (the final working
payload) but not the *journey* (the failed attempts, the discovery process).
Rather than try to scrape and paraphrase thousands of third-party writeups'
prose at scale -- which is both legally messy and unreliable to automate --
this project separates the two things that are actually reusable:

1. **The generic process.** For ~35 vulnerability classes, [`knowledge/vulnerability_playbooks.json`](knowledge/vulnerability_playbooks.json)
   defines an originally-authored preconditions/steps/impact/remediation
   playbook -- the reusable "how do you generally find and fix this."
2. **The grounding instance.** Public metadata (title, vulnerability class,
   severity, program, disclosure date, and a link) from a real disclosed
   report or writeup, sourced from public APIs/feeds that already publish
   this metadata for reuse.

Every record in the dataset merges one of each into a single, self-contained,
schema-validated JSON object. See [`DATA_LICENSE`](DATA_LICENSE) for exactly
what is and isn't reproduced from the original sources.

## Dataset snapshot

`data/scenarios/scenarios.jsonl` -- **7,342 records**, one JSON object per line.

| Source | Platform | Records |
|---|---|---|
| Pentester Land curated writeup index | `aggregated_writeup` | 5,498 |
| GitHub TryHackMe room-writeup repos | `tryhackme` | 1,367 |
| HackerOne public Hacktivity (GraphQL API) | `hackerone` | 393 |
| GitHub CTF writeup repositories | `ctf` | 84 |

Top vulnerability classes by record count: TryHackMe general room-solving
process (1,280 -- see note below), Broken Access Control (735), Sensitive
Information Disclosure (692), Reflected XSS (660), Account Takeover (416),
RCE (354), IDOR (287), Business Logic Flaws (265), SSRF (239) -- 37 classes
total, see [`knowledge/vulnerability_playbooks.json`](knowledge/vulnerability_playbooks.json)
for the full list.

74% of records (5,451) are `confidence: "high"` classification matches; see
[`docs/SCHEMA.md`](docs/SCHEMA.md#confidence-levels) to filter for precision.
TryHackMe room titles are often thematic ("Blue", "Ice") rather than
vulnerability-descriptive, so most of them fall back to the generic
`tryhackme_room_generic` playbook (`confidence: "low"`) rather than a specific
vulnerability class -- filter to `confidence: "high"` if you only want
precisely classified records.

## Finding records: three ways to consume the dataset

A single 7,342-line JSONL file isn't practical to browse or filter by hand,
so the dataset ships in three forms, all derived from the same source of
truth:

1. **`data/scenarios/scenarios.jsonl`** -- the canonical file, one record per
   line. Best for bulk loading (e.g. `datasets.load_dataset("json", data_files=...)`
   in Python) or streaming the whole thing.
2. **`data/scenarios/by_class/<playbook_id>.jsonl`** -- the same records
   split per vulnerability class (37 files), so you can open or download just
   `by_class/sqli.jsonl` or `by_class/ssrf.jsonl` directly.
3. **`data/index.sqlite3`** -- a pre-built, indexed SQLite database (indexed
   on CWE, severity, platform, playbook_id, target_type, confidence, plus an
   FTS5 full-text index) for actual filtering. Query it directly with `sqlite3`,
   or use the bundled CLI:

   ```bash
   cd scripts
   python3 query.py --cwe CWE-89                          # by CWE
   python3 query.py --playbook ssrf --severity high        # by class + severity
   python3 query.py --platform tryhackme --playbook sqli   # by source + class
   python3 query.py --search "cache poisoning"             # full-text search
   python3 query.py --cwe CWE-639 --json                   # full record JSON out
   python3 query.py                                        # no filters -> lists all playbook_ids/platforms
   ```

## Repo layout

```
schema/scenario.schema.json        Canonical JSON Schema for one scenario record
schema/graph.schema.json           Canonical JSON Schema for the attack graph
knowledge/vulnerability_playbooks.json   Authored generic playbooks (the "process" library)
knowledge/graph/bridges.json       Authored cross-class chaining states/actions (the graph's design work)
scripts/collect_hackerone.py       Public HackerOne Hacktivity metadata collector
scripts/collect_pentesterland.py   Pentester Land curated writeup-link collector
scripts/collect_ctf.py             GitHub CTF-writeup-repo collector (topic search)
scripts/collect_tryhackme.py       GitHub TryHackMe room-writeup collector (cross-repo dedup)
scripts/normalize.py               Classifies raw records against playbooks, emits unified schema
scripts/validate.py                JSON Schema + dedup validation
scripts/build_views.py             Builds the by-class split and the SQLite index
scripts/query.py                   CLI for filtering/searching the scenario dataset via the SQLite index
scripts/build_graph.py             Generates per-class graph chains from playbooks, merges in bridges.json
scripts/validate_graph.py          Graph schema + referential integrity + reachability validation
scripts/query_graph.py             CLI for traversing the graph / finding candidate attack paths
scripts/pipeline.sh                Runs the full chain: collect -> normalize -> validate -> build_views -> build_graph
data/scenarios/scenarios.jsonl     The canonical published scenario dataset
data/scenarios/by_class/           Same records, split per vulnerability class
data/index.sqlite3                 Indexed + full-text-searchable SQLite view of the scenario dataset
data/graph/attack_graph.json       The generated attack decision graph (states + actions)
data/raw/                          Ephemeral collector output (gitignored, regenerate locally)
docs/SCHEMA.md                     Scenario record field-by-field reference
docs/GRAPH.md                      Attack graph design + query_graph.py usage
```

## Regenerating / extending the dataset

```bash
pip install -r requirements.txt   # jsonschema (stdlib urllib/sqlite3 handle the rest)
cd scripts
./pipeline.sh 15 0 30 20           # hackerone_pages, pentesterland_limit(0=all), ctf_per_page, thm_repos_per_topic
```

Each collector can also be run standalone and re-normalized independently --
see the docstring at the top of each `scripts/*.py` file. After changing
`data/scenarios/scenarios.jsonl` by hand or via `normalize.py`, re-run
`python3 build_views.py` to keep `by_class/` and `index.sqlite3` in sync.

### Avoiding duplicates across many small repos (TryHackMe)

Unlike HackerOne/Pentester Land (one canonical URL per report/writeup),
dozens of independent GitHub repos write up the same popular TryHackMe room
("Blue", "Ice", ...). `collect_tryhackme.py` dedups by **normalized room
title**, not just by URL: repos are processed most-starred-first, and only
the first occurrence of each room title is kept, so a room is attributed to
its most reputable available source instead of appearing dozens of times.

### Adding a vulnerability class

Add an entry to `knowledge/vulnerability_playbooks.json` with a unique
`playbook_id`, `aliases` (the tag/keyword strings that should match it), and
the four `scenario` sub-fields. Re-run `normalize.py` -- previously
unclassified raw records may now match. Re-run `build_graph.py` too: the new
class's linear chain is generated automatically, but it won't connect to
anything else in the graph until you also add bridge action(s) for it in
`knowledge/graph/bridges.json` (see [`docs/GRAPH.md`](docs/GRAPH.md)).

### Adding a chain to the attack graph

Edit `knowledge/graph/bridges.json`: add any new shared state(s) to `states`,
and an action to `actions` with `from_state` set to an existing
`{playbook_id}_confirmed` state (or another bridge state) and one or more
`outcomes` pointing at `to_state`s. Then:

```bash
python3 build_graph.py
python3 validate_graph.py   # checks schema + that every from_state/to_state exists + reachability
```

### Adding a data source

Write a new `scripts/collect_<source>.py` that writes one JSON object per
line to `data/raw/<source>.jsonl`, following the field conventions of the
existing collectors (`source_platform`, `title`, `url` are the minimum).
`normalize.py` picks up any `*.jsonl` file in `data/raw/` automatically --
you'll also need a small classification branch in `build_record()` for the
new platform's field names.

**Roadmap / not yet implemented:** Bugcrowd disclosed-report scraping (no
stable public API found; would need a robots.txt-respecting HTML collector),
and deeper full-text extraction for higher-fidelity, per-instance steps
(would require an LLM-assisted normalization pass -- `normalize.py` is
structured so a `--llm` mode could be added without changing the schema).

## Known limitations

- `scenario.process` is a generic playbook per vulnerability class, not a
  transcription of the specific instance's actual steps -- see "Why this
  shape" above. This is a deliberate trade-off for legal safety and
  automation at scale, not a bug.
- Severity is `"unknown"` for ~95% of records: HackerOne's severity rating
  requires authentication to read for most reports, and Pentester Land's feed
  doesn't carry a severity field at all.
- Classification is keyword/alias-based, not semantic -- see `confidence` in
  each record.

## License

Code (`scripts/`, `schema/`): [MIT](LICENSE).
Data (`data/`, `knowledge/`): [CC BY 4.0](DATA_LICENSE).
