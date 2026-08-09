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
generic vulnerability classes, 8 real specific CVE chains (Log4Shell,
Spring4Shell, the Confluence/GitLab/Struts/Citrix/Exchange/Laravel RCEs --
CVE IDs and CVSS scores verified against NVD), and 9 AI/LLM classes (prompt
injection, excessive agency, insecure output handling, ...) all converge and
chain through a shared vocabulary of hand-authored bridge states -- e.g.
every RCE-capable class or CVE converges on `low_priv_shell_obtained`, SSRF
can chain into `cloud_metadata_reachable -> cloud_credentials_obtained ->
full_cloud_account_compromise`, and -- the interesting one -- a prompt
injection that abuses an over-scoped agent tool converges on the exact same
`unauthorized_privileged_action_possible` state that IDOR or mass assignment
reach: AI-specific and classic web vulnerabilities landing on the same
attacker objective through different paths, not two separate graphs bolted
together. Each state also carries `detection_signals`: authored hints (not
a working classifier) for recognizing it from real tool output -- e.g. what
a metadata credentials response actually looks like, or what a root shell's
`id` output looks like.

```bash
cd scripts
python3 query_graph.py --from web_target_identified                                    # candidate first moves
python3 query_graph.py --best-path --from ssrf_confirmed --to full_cloud_account_compromise   # a strong path to a goal
```

**Turning the static graph into training data**: `scripts/simulate_graph.py`
samples synthetic episodes from it -- repeatedly walking the graph from an
entry state, sampling outcomes by their authored likelihood, scoring with a
proper Bellman value function (not just 1-step lookahead, which is flat
across most early recon states) -- and logs full (state, action, outcome,
reward) trajectories:

```bash
python3 simulate_graph.py --episodes 3000 --policy random --out ../data/graph/episodes_random.jsonl
python3 simulate_graph.py --episodes 1000 --policy greedy --out ../data/graph/episodes_greedy.jsonl
```

On the current graph, the value-iteration-informed greedy policy reaches a
`full_compromise` state **13.1%** of the time vs **5.3%** for a uniformly
random policy -- a real, if modest, measurable gap. This is still bootstrapped
from the graph's own authored priors, not ground truth (see caveat below and
in `docs/GRAPH.md`) -- but it's a materially different artifact than the
static graph: many diverse, complete trajectories rather than one structure.

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

`data/scenarios/scenarios.jsonl` -- **16,225 records**, one JSON object per line.

| Source | Platform | Records |
|---|---|---|
| HackerOne public Hacktivity (GraphQL API) | `hackerone` | 7,897 |
| Pentester Land + 2 curated GitHub lists + 3 Medium publication RSS feeds | `aggregated_writeup` | 5,768 |
| GitHub TryHackMe room-writeup repos | `tryhackme` | 2,391 |
| GitHub CTF writeup repositories | `ctf` | 169 |

The Medium feeds (InfoSec Write-ups, System Weakness, OSINT Team --
`scripts/collect_medium_feeds.py`, via each publication's own RSS `/feed`)
only return their ~10 most recent posts per fetch; re-running the collector
periodically accumulates more as new articles publish, deduped
automatically by URL.

HackerOne is now a **full pull of every currently disclosed report**
(12,386 fetched, ~4,489 didn't match a recognized vulnerability class and
were dropped rather than force-classified). 46 vulnerability classes total
(35 generic + 9 AI/LLM, see below), see
[`knowledge/vulnerability_playbooks.json`](knowledge/vulnerability_playbooks.json)
for the full list.

74% of records are `confidence: "high"` classification matches; see
[`docs/SCHEMA.md`](docs/SCHEMA.md#confidence-levels) to filter for precision.
TryHackMe room titles are often thematic ("Blue", "Ice") rather than
vulnerability-descriptive, so most of them fall back to the generic
`tryhackme_room_generic` playbook (`confidence: "low"`) rather than a specific
vulnerability class -- filter to `confidence: "high"` if you only want
precisely classified records.

**Cross-source deduplication**: Pentester Land and the curated GitHub lists
sometimes link to the same HackerOne report we already pulled directly.
`normalize.py` dedups by URL *across* platforms (not just within one),
preferring the more precisely-classified HackerOne-native record when both
exist -- 506 cross-platform duplicates were dropped this way, on top of the
usual per-source dedup.

### AI/LLM vulnerability classes

9 new playbooks cover the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
(all except LLM09 Misinformation, which isn't a testable technical
vulnerability the way the others are): prompt injection (CWE-1427),
sensitive information disclosure, supply chain, data/model poisoning,
improper output handling (CWE-1426), excessive agency, system prompt
leakage, vector/embedding weaknesses, and unbounded consumption. They're
fully wired into the attack graph (see below) -- but honestly, real-world
grounded instances are scarce right now: only **prompt injection (22
records)** and **model DoS (1 record)** matched anything in the sources
above, because "Prompt Injection" is only just emerging as a tag bug
hunters actually use; the other 8 classes have zero grounded instances yet.
The playbooks and graph chains are ready the moment real writeups start
using this terminology, or via community submission (see below).

### A note on scale

An earlier ask for this project was "extend this to 100k unique writeups."
Here's the honest accounting: pushing every legitimate source available as
far as it goes -- a full pull of HackerOne's disclosed reports (not a
sample), Pentester Land's complete index, two more curated GitHub
writeup-list repos, and a much wider TryHackMe/CTF repo search -- got the
dataset from 7,342 to **16,225** unique records. That's real growth, not
padding (every record is schema-validated, source-linked, and deduplicated
by URL across sources). It's not 100k.

Three platforms that could plausibly have gotten closer were checked and
ruled out rather than worked around:
- **Open Bug Bounty** sits behind a Cloudflare bot-detection challenge --
  bypassing that isn't something this project will do.
- **Intigriti**'s API requires an authenticated account; there's no public,
  unauthenticated equivalent to HackerOne's Hacktivity API.
- **Bugcrowd**'s public `crowdstream` is a live *submission-acceptance*
  feed, not a disclosure archive -- almost none of it has `disclosed` set,
  so there's little actual writeup content to collect from it.

Reaching 100k for real would mean either scraping full writeup bodies from
thousands of individual blogs at scale (the copyright problem this project
has deliberately avoided since day one -- see `DATA_LICENSE`) or padding
with low-relevance filler, which would break the "trusted good writeups"
bar this was supposed to meet. The contribution mechanism below is the
actual intended path past this ceiling: platform disclosure counts grow
over time on their own, and every real submission adds a record no
automated collector could have found.

## Contributing a writeup

Anyone can submit a writeup link without touching JSON or the schema:
[open an issue using the "Submit a writeup" template](../../issues/new?template=submit-writeup.yml).
It asks for the URL, title, author, program, and vulnerability tags --
metadata only, same policy as every other source in this dataset (see
`DATA_LICENSE`): we link to your writeup, we don't copy it.

For maintainers processing a submission:

```bash
cd scripts
python3 ingest_submissions.py --from-issue 42   # parses the issue form via `gh issue view`
# or manually:
python3 ingest_submissions.py --url https://... --title "..." --tags "IDOR,SSRF"

# fold it into the published dataset:
cp ../knowledge/community_submissions.jsonl ../data/raw/community_submissions.jsonl
python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl
python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json
python3 build_views.py --data ../data/scenarios/scenarios.jsonl --by-class-dir ../data/scenarios/by_class --db ../data/index.sqlite3
```

Unlike `data/raw/*.jsonl` from the API/feed collectors (ephemeral,
re-fetchable, gitignored), `knowledge/community_submissions.jsonl` is
committed directly -- it's real human contribution, not something a script
can regenerate. Every PR that touches the dataset or graph is checked by
[`.github/workflows/validate.yml`](.github/workflows/validate.yml):
schema validation, referential integrity, and a check that the committed
`attack_graph.json`/`by_class/` files actually match what their source
files would regenerate.

## Using this dataset: RAG, not raw fine-tuning

`scenarios.jsonl` repeats the same ~35 authored playbook texts across 7,342
records with different source-metadata wrappers. That's fine, even good, for
**retrieval** -- look up "what do I know about SSRF," get back the playbook
plus real grounding links. It's a poor fit for **supervised fine-tuning as
a raw dump**: training on it directly would mostly teach a model to
memorize ~35 canned answers repeated thousands of times, not to generalize.

If you're building a RAG pipeline: run `python3 scripts/build_views.py`
once, then use `data/index.sqlite3` or `data/scenarios/by_class/` directly,
keyed by CWE/class/tag as needed.

If you want fine-tuning data anyway (e.g. as one ingredient in a larger SFT
mix, or an eval set): `scripts/sample_balanced.py` caps how many records any
one vulnerability class can contribute and prefers higher-confidence
matches, instead of naively oversampling whatever source collected the most
raw records:

```bash
cd scripts
python3 sample_balanced.py --max-per-class 20 --min-confidence medium --out ../data/scenarios/balanced_sample.jsonl
```

For anything closer to actual **decision-making/RL training data**, the
[attack graph](#beyond-a-flat-list-the-attack-decision-graph) and its
simulator are the better starting point -- see below.

## Finding records: three ways to consume the dataset

A single 16,225-line JSONL file isn't practical to browse or filter by hand.
Only one form of the dataset is committed to the repo -- the other two are
generated locally in seconds, not shipped, so the repo stays clonable:

1. **`data/scenarios/scenarios.jsonl`** (committed, ~47MB) -- the canonical
   file, one record per line. Best for bulk loading (e.g.
   `datasets.load_dataset("json", data_files=...)` in Python) or streaming
   the whole thing.
2. **`data/scenarios/by_class/<playbook_id>.jsonl`** (git-ignored, build
   locally) -- the same records split per vulnerability class, so you can
   work with just `by_class/sqli.jsonl` or `by_class/ssrf.jsonl` without
   loading everything.
3. **`data/index.sqlite3`** (git-ignored, build locally) -- an indexed
   SQLite database (CWE, severity, platform, playbook_id, target_type,
   confidence, plus an FTS5 full-text index) for actual filtering.

Build both in one step, no arguments needed:

```bash
cd scripts
python3 build_views.py
```

Then query it directly with `sqlite3`, or use the bundled CLI:

```bash
python3 query.py --cwe CWE-89                          # by CWE
python3 query.py --playbook ssrf --severity high        # by class + severity
python3 query.py --platform tryhackme --playbook sqli   # by source + class
python3 query.py --search "cache poisoning"             # full-text search
python3 query.py --cwe CWE-639 --json                   # full record JSON out
python3 query.py                                        # no filters -> lists all playbook_ids/platforms
```

**Why these two aren't committed**: both are 100% mechanically derived from
`scenarios.jsonl` -- shipping them meant storing the same ~16k records
three times over (scenarios.jsonl + by_class + inside the SQLite rows),
which is how the repo hit ~179MB and tripped GitHub's recommended
50MB-per-file warning on the SQLite index. `build_views.py` regenerates
both from the one committed source of truth in well under a minute; CI
runs it on every push to catch drift (record-count check against
`scenarios.jsonl`), it just doesn't commit the output.

## Repo layout

```
.github/ISSUE_TEMPLATE/submit-writeup.yml  Structured writeup-submission issue form
.github/workflows/validate.yml     CI: schema/graph validation on every push and PR
schema/scenario.schema.json        Canonical JSON Schema for one scenario record
schema/graph.schema.json           Canonical JSON Schema for the attack graph
knowledge/vulnerability_playbooks.json   Authored generic + AI/LLM playbooks (the "process" library)
knowledge/graph/bridges.json       Authored cross-class chaining states/actions (the graph's design work)
knowledge/graph/technology_bridges.json  Authored real-CVE technology chains (Log4Shell, Spring4Shell, etc.)
knowledge/graph/ai_bridges.json    Authored AI/LLM chaining actions (reuse existing capability states, add none)
knowledge/community_submissions.jsonl    Committed log of writeups submitted via the issue template
scripts/collect_hackerone.py       Public HackerOne Hacktivity metadata collector
scripts/collect_pentesterland.py   Pentester Land curated writeup-link collector
scripts/collect_curated_lists.py   Additional curated GitHub writeup-list collectors
scripts/collect_medium_feeds.py    Medium publication RSS feed collector (InfoSec Write-ups, etc.)
scripts/collect_ctf.py             GitHub CTF-writeup-repo collector (topic search)
scripts/collect_tryhackme.py       GitHub TryHackMe room-writeup collector (cross-repo dedup)
scripts/ingest_submissions.py      Converts an issue-form submission into community_submissions.jsonl
scripts/normalize.py               Classifies raw records against playbooks, emits unified schema (cross-platform URL dedup)
scripts/validate.py                JSON Schema + dedup validation
scripts/build_views.py             Builds the by-class split and the SQLite index
scripts/query.py                   CLI for filtering/searching the scenario dataset via the SQLite index
scripts/sample_balanced.py         Class-balanced, confidence-preferring subset for fine-tuning use
scripts/build_graph.py             Generates per-class graph chains from playbooks, merges in the bridge files
scripts/validate_graph.py          Graph schema + referential integrity + reachability validation
scripts/query_graph.py             CLI for traversing the graph / finding candidate attack paths
scripts/simulate_graph.py          Samples synthetic (state, action, outcome, reward) episodes from the graph
scripts/pipeline.sh                Runs the full chain: collect -> normalize -> validate -> build_views -> build_graph
data/scenarios/scenarios.jsonl     The canonical published scenario dataset
data/scenarios/by_class/           Same records, split per vulnerability class (gitignored, `build_views.py`)
data/scenarios/balanced_sample.jsonl   Class-balanced subset (see "Using this dataset")
data/index.sqlite3                 Indexed + full-text-searchable SQLite view (gitignored, `build_views.py`)
data/graph/attack_graph.json       The generated attack decision graph (states + actions)
data/graph/episodes_*.jsonl        Simulated episodes per policy (random / greedy / epsilon_greedy)
data/raw/                          Ephemeral collector output (gitignored, regenerate locally)
docs/SCHEMA.md                     Scenario record field-by-field reference
docs/GRAPH.md                      Attack graph design, detection signals, technology chains, simulator
```

## Regenerating / extending the dataset

```bash
pip install -r requirements.txt   # jsonschema (stdlib urllib/sqlite3 handle the rest)
cd scripts
./pipeline.sh                      # defaults reproduce the full ~16.2k-record run (takes a few minutes)
./pipeline.sh 10 0 20 10           # or pass smaller numbers for a quick local test: hackerone_pages, pentesterland_limit(0=all), ctf_per_page, thm_repos_per_topic
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
- 8 of the 9 new AI/LLM classes have zero real grounded instances yet
  (only prompt injection and model DoS matched anything) -- see "AI/LLM
  vulnerability classes" above.
- Not 100k records -- see "A note on scale" above for exactly which sources
  were tried, which were ruled out, and why.
- **Repo size**: `data/index.sqlite3` and `data/scenarios/by_class/` are no
  longer committed (they're 100% derived from `scenarios.jsonl` --
  regenerate with `python3 scripts/build_views.py`), which is what actually
  fixed the growth problem noted in earlier versions of this doc rather than
  just working around it. `scenarios.jsonl` itself (~47MB) still grows with
  every new source and every community submission, which is expected and
  fine -- it's real, non-duplicated data. If it eventually gets large enough
  to matter on its own, Git LFS is the next lever, not before.

## License

Code (`scripts/`, `schema/`): [MIT](LICENSE).
Data (`data/`, `knowledge/`): [CC BY 4.0](DATA_LICENSE).
