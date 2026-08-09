# The attack decision graph

`data/graph/attack_graph.json` is a second, complementary artifact to the
flat scenario dataset (`data/scenarios/`). Where the scenario dataset answers
"how do I find and fix vulnerability class X," the graph answers "given what
I've established so far, what should I try next, and where might that lead" --
the same shape of question a chess engine answers by evaluating candidate
moves and their resulting positions.

## Shape

Two node/edge types, validated against [`schema/graph.schema.json`](../schema/graph.schema.json):

- **States** -- a condition or capability that has been established (e.g.
  `web_target_identified`, `idor_confirmed`, `low_priv_shell_obtained`,
  `full_host_compromise`). Each has a `tier` (where it sits in the kill
  chain) and a `value` (how good this position is, like a chess evaluation).
- **Actions** -- a move attemptable from one state, branching into 1+
  possible **outcomes**, each with a qualitative `likelihood` (rare /
  possible / likely) and the resulting `to_state`.

```jsonc
// a state
{"state_id": "idor_confirmed", "tier": "vulnerability_confirmed", "value": "high", ...}

// an action from that state
{
  "action_id": "bridge_idor_to_privileged_action",
  "from_state": "idor_confirmed",
  "action": "Exploit the write/delete IDOR against another user's or an administrative object.",
  "outcomes": [
    {"outcome_id": "success", "likelihood": "possible", "to_state": "unauthorized_privileged_action_possible", ...},
    {"outcome_id": "read_only", "likelihood": "likely", "to_state": "idor_confirmed", "note": "Still reportable..."}
  ]
}
```

## Two layers

1. **Generated per-class chains** (`scripts/build_graph.py`, mechanical):
   each of the 35 real vulnerability playbooks in
   `knowledge/vulnerability_playbooks.json` becomes a linear chain --
   `{target_type}_target_identified -> ... -> {playbook_id}_confirmed`, with
   every step also branching to a `{playbook_id}_ruled_out` dead end on
   failure. (`ctf_challenge_generic` and `tryhackme_room_generic` are
   excluded -- they're meta-processes, not a vulnerability class to chain
   from.)

2. **Hand-authored bridges** (`knowledge/graph/bridges.json`, the actual
   design work): 15 shared capability/privileged_access/full_compromise
   states and 45 actions connecting per-class `_confirmed` states into that
   shared vocabulary -- and into each other. This is what makes it a graph
   instead of 35 disconnected trees: six different RCE-capable classes
   (command injection, deserialization, SSTI, file upload, generic RCE,
   memory corruption) all converge on `low_priv_shell_obtained`; SSRF can
   reach `cloud_metadata_reachable` -> `cloud_credentials_obtained` ->
   `full_cloud_account_compromise`; a leaked secret
   (`hardcoded_secrets_confirmed`) can grant either app-level or cloud
   access depending on what it validates against.

Run `scripts/build_graph.py` to regenerate the merged output after editing
either source file.

## Using it: `scripts/query_graph.py`

```bash
cd scripts

# What are my candidate first moves from a fresh web target?
python3 query_graph.py --from web_target_identified

# Look 2 moves ahead
python3 query_graph.py --from web_target_identified --depth 2

# Inspect one state: what leads into it, what leads out of it
python3 query_graph.py --state idor_confirmed

# Find a strong path toward a goal (greedy best-first search over
# cumulative value x likelihood score)
python3 query_graph.py --best-path --from web_target_identified --to full_application_compromise
python3 query_graph.py --best-path --from ssrf_confirmed --to full_cloud_account_compromise
```

Example output for the last command:

```
Path found, cumulative heuristic score = 26.0 (3 hops)

ssrf_confirmed [vulnerability_confirmed/high]
  --[bridge_ssrf_to_cloud_metadata (bridge): Redirect the SSRF toward the cloud instance metadata service.]--> (possible)
cloud_metadata_reachable [capability/high]
  --[bridge_cloud_metadata_to_creds (bridge): Query the metadata service's security-credentials endpoint.]--> (likely)
cloud_credentials_obtained [capability/critical]
  --[bridge_cloud_creds_to_access (bridge): Enumerate IAM permissions and accessible resources for the obtained cloud credentials.]--> (possible)
full_cloud_account_compromise [full_compromise/critical]
```

### `--best-path` is heuristic, not optimal

`likelihood` and `value` are authored security judgment, not measured
probabilities or impact data -- there's no telemetry backing them (see
[`DATA_LICENSE`](../DATA_LICENSE)). The search itself is greedy best-first
over cumulative score, bounded by `--max-expansions`/`--max-depth`, not an
exhaustive optimal-path solver. Treat its output as "a reasonable candidate
path a competent tester might take," not a provably best attack plan.

## Stats

199 states, 189 actions (144 generated from playbooks + 15 bridge states /
45 bridge actions hand-authored). Validated with zero schema errors, zero
unreachable states (`scripts/validate_graph.py`).
