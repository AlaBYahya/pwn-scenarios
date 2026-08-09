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

## Why this shape

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

`data/scenarios/scenarios.jsonl` -- **5,975 records**, one JSON object per line.

| Source | Platform | Records |
|---|---|---|
| HackerOne public Hacktivity (GraphQL API) | `hackerone` | 393 |
| Pentester Land curated writeup index | `aggregated_writeup` | 5,498 |
| GitHub CTF writeup repositories | `ctf` | 84 |

Top vulnerability classes by record count: Broken Access Control (729),
Sensitive Information Disclosure (684), Reflected XSS (653), Account Takeover
(416), RCE (353), IDOR (285), Business Logic Flaws (265), SSRF (235) -- 36
classes total, see [`knowledge/vulnerability_playbooks.json`](knowledge/vulnerability_playbooks.json)
for the full list.

90% of records (5,362) are `confidence: "high"` classification matches; see
[`docs/SCHEMA.md`](docs/SCHEMA.md#confidence-levels) to filter for precision.

## Repo layout

```
schema/scenario.schema.json        Canonical JSON Schema for one record
knowledge/vulnerability_playbooks.json   Authored generic playbooks (the "process" library)
scripts/collect_hackerone.py       Public HackerOne Hacktivity metadata collector
scripts/collect_pentesterland.py   Pentester Land curated writeup-link collector
scripts/collect_ctf.py             GitHub CTF-writeup-repo collector (topic search)
scripts/normalize.py               Classifies raw records against playbooks, emits unified schema
scripts/validate.py                JSON Schema + dedup validation
scripts/pipeline.sh                Runs collect -> normalize -> validate end to end
data/scenarios/scenarios.jsonl     The published dataset
data/raw/                          Ephemeral collector output (gitignored, regenerate locally)
docs/SCHEMA.md                     Field-by-field reference
```

## Regenerating / extending the dataset

```bash
pip install -r requirements.txt   # jsonschema (stdlib urllib handles HTTP)
cd scripts
./pipeline.sh 15 0 30              # hackerone_pages, pentesterland_limit(0=all), ctf_per_page
```

Each collector can also be run standalone and re-normalized independently --
see the docstring at the top of each `scripts/*.py` file.

### Adding a vulnerability class

Add an entry to `knowledge/vulnerability_playbooks.json` with a unique
`playbook_id`, `aliases` (the tag/keyword strings that should match it), and
the four `scenario` sub-fields. Re-run `normalize.py` -- previously
unclassified raw records may now match.

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
