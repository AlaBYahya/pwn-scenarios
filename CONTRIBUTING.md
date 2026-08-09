# Contributing

Issues and PRs welcome. A few useful entry points:

- **New vulnerability class or a better playbook**: edit
  `knowledge/vulnerability_playbooks.json`, then run
  `python3 scripts/normalize.py` and `python3 scripts/validate.py` to confirm
  it still validates.
- **New data source**: see the "Adding a data source" section in the README.
- **New attack-graph chain / bridge**: edit `knowledge/graph/bridges.json`
  (generic) or `knowledge/graph/technology_bridges.json` (a specific CVE --
  please verify the CVE ID and CVSS against [NVD](https://nvd.nist.gov/)
  first), then run `python3 scripts/build_graph.py` and
  `python3 scripts/validate_graph.py`. See [`docs/GRAPH.md`](docs/GRAPH.md).
  After changing the graph, re-run `python3 scripts/simulate_graph.py`
  (random + greedy) if you want updated episode files -- not required for a
  PR, but useful to sanity-check that greedy still clearly beats random
  (a collapse in that gap can indicate a broken/disconnected bridge).
- **Bad classification / wrong playbook match**: open an issue with the
  record's `id` and `source.url`; classification is keyword-based
  (`scripts/normalize.py`) and easy to get wrong on ambiguous tags.
- **Takedown request**: if you're the author of a linked writeup and want its
  metadata removed, open an issue with the `source.url`.

Before submitting a PR that touches `data/scenarios/scenarios.jsonl`, run the
full chain so `by_class/` and `index.sqlite3` stay in sync with it:

```bash
cd scripts
python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl
python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json
python3 build_views.py --data ../data/scenarios/scenarios.jsonl --by-class-dir ../data/scenarios/by_class --db ../data/index.sqlite3
```
