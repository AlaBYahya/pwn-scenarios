# Contributing

Issues and PRs welcome. A few useful entry points:

- **Submitting a writeup** (no JSON/schema knowledge needed): use the
  ["Submit a writeup" issue template](../../issues/new?template=submit-writeup.yml).
  See "Contributing a writeup" in the README for how it gets folded into the
  dataset (`scripts/ingest_submissions.py`).
- **New vulnerability class or a better playbook**: see "Adding a
  vulnerability class" below.
- **New data source**: see "Adding a data source" below.
- **New attack-graph chain / bridge**: see "Adding a chain to the attack
  graph" below. See also [`docs/GRAPH.md`](docs/GRAPH.md) for the graph's
  full design.
- **Bad classification / wrong playbook match**: open an issue with the
  record's `id` and `source.url`; classification is keyword-based
  (`scripts/normalize.py`) and easy to get wrong on ambiguous tags.
- **Takedown request**: if you're the author of a linked writeup and want its
  metadata removed, open an issue with the `source.url`.

### Adding a vulnerability class

Add an entry to `knowledge/vulnerability_playbooks.json` with a unique
`playbook_id`, `aliases` (the tag/keyword strings that should match it), and
the four `scenario` sub-fields. Re-run `normalize.py` -- previously
unclassified raw records may now match. Re-run `build_graph.py` too: the new
class's linear chain is generated automatically, but it won't connect to
anything else in the graph until you also add bridge action(s) for it in
`knowledge/graph/bridges.json`.

### Adding a chain to the attack graph

Edit `knowledge/graph/bridges.json` (generic capability chains) or
`knowledge/graph/technology_bridges.json` (a specific CVE -- please verify
the CVE ID and CVSS against [NVD](https://nvd.nist.gov/) first): add any new
state(s) to `states`, and an action to `actions` with `from_state` set to an
existing `{playbook_id}_confirmed` state (or another bridge state) and one
or more `outcomes` pointing at `to_state`s. Then:

```bash
cd scripts
python3 build_graph.py      # regenerate the merged graph
python3 validate_graph.py   # checks schema + that every from_state/to_state exists + reachability
```

Re-run `python3 simulate_graph.py` (random + greedy) if you want updated
episode files -- not required for a PR, but useful to sanity-check that
greedy still clearly beats random (a collapse in that gap can indicate a
broken/disconnected bridge).

### Adding a data source

Write a new `scripts/collect_<source>.py` that writes one JSON object per
line to `data/raw/<source>.jsonl`, following the field conventions of the
existing collectors (`source_platform`, `title`, `url` are the minimum).
`normalize.py` picks up any `*.jsonl` file in `data/raw/` automatically --
you'll also need a small classification branch in `build_record()` for the
new platform's field names. Only add sources you've confirmed are fair to
collect: public RSS/Atom feeds, sitemaps with `robots.txt: Allow: /`, public
unauthenticated APIs, or plain CSV/markdown files in a repo -- not sites
that gate content behind auth or bot-detection, or whose `robots.txt`
disallows the path (see `CHANGELOG.md` for sources already evaluated and
rejected, and why).

Before submitting a PR that touches `data/scenarios/scenarios.jsonl`, run:

```bash
cd scripts
python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl
python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json
python3 build_views.py   # sanity-checks by_class/ and the SQLite index build cleanly; neither is committed
```

`by_class/` and `index.sqlite3` are gitignored -- don't `git add` them, CI
regenerates and sanity-checks them itself on every push.
