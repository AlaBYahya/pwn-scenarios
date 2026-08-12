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

Optionally, a state also carries `detection_signals` (hints for recognizing
it from real tool output -- see below), and technology-specific states carry
`technology` and `cve_refs`.

## Four layers

1. **Generated per-class chains** (`scripts/build_graph.py`, mechanical):
   each of the 44 real vulnerability playbooks (35 generic + 9 AI/LLM) in
   `knowledge/vulnerability_playbooks.json` becomes a linear chain --
   `{target_type}_target_identified -> ... -> {playbook_id}_confirmed`, with
   every step also branching to a `{playbook_id}_ruled_out` dead end on
   failure. (`ctf_challenge_generic` and `tryhackme_room_generic` are
   excluded -- they're meta-processes, not a vulnerability class to chain
   from.) Each generated state gets a mechanically-derived `detection_signals`
   entry from the underlying playbook step's `expected_observation`.

2. **Hand-authored generic bridges** (`knowledge/graph/bridges.json`, the
   core design work): 21 shared capability/privileged_access/full_compromise
   states (15 new + 6 detection-signal-enriched overrides of the highest-value
   `_confirmed` states) and 45 actions connecting per-class `_confirmed`
   states into that shared vocabulary -- and into each other. This is what
   makes it a graph instead of 35 disconnected trees: six different
   RCE-capable classes (command injection, deserialization, SSTI, file
   upload, generic RCE, memory corruption) all converge on
   `low_priv_shell_obtained`; SSRF can reach `cloud_metadata_reachable` ->
   `cloud_credentials_obtained` -> `full_cloud_account_compromise`; a leaked
   secret (`hardcoded_secrets_confirmed`) can grant either app-level or cloud
   access depending on what it validates against.

3. **Hand-authored technology/CVE bridges** (`knowledge/graph/technology_bridges.json`):
   the generic playbooks are deliberately technology-agnostic ("test for
   SQLi"), which misses where a lot of real bug bounty value actually
   concentrates -- specific, known-critical CVEs in specific software. This
   layer adds **17 real, patched CVE chains** with CVE IDs and CVSS scores
   verified against NVD: **Log4Shell** (CVE-2021-44228, CVSS 10.0),
   **Spring4Shell** (CVE-2022-22965, 9.8), **Confluence OGNL injection**
   (CVE-2022-26134, 9.8), **GitLab ExifTool RCE** (CVE-2021-22205, 10.0),
   **Laravel Ignition debug RCE** (CVE-2021-3129, 9.8), **Apache Struts
   Jakarta Multipart RCE** (CVE-2017-5638, 9.8 -- the Equifax breach cause),
   **Citrix ADC directory traversal** (CVE-2019-19781, 9.8), the **Exchange
   ProxyLogon/ProxyShell family** (CVE-2021-26855 + CVE-2021-34473, modeled
   as one consolidated step -- the real chain involves multiple intermediate
   CVEs), **Zerologon** (CVE-2020-1472, 5.5, netlogon auth bypass to domain
   admin), **EternalBlue** (CVE-2017-0144, 8.8, the WannaCry/NotPetya SMB
   worm), **PrintNightmare** (CVE-2021-34527, 8.8), **Follina** (CVE-2022-30190,
   7.8, MSDT RCE via Office), **MOVEit Transfer** (CVE-2023-34362, 9.8, the
   Cl0p mass-exploitation chain), **Citrix Bleed** (CVE-2023-4966, 9.4,
   session-token leak from the same ADC fingerprint state Citrix traversal
   uses), **Cisco IOS XE web UI RCE** (CVE-2023-20198, 10.0), the **Ivanti
   Connect Secure chain** (CVE-2023-46805 auth bypass + CVE-2023-21887
   command injection), and a **GitLab unauthenticated password-reset account
   takeover** (CVE-2023-7028, 10.0, reusing the existing GitLab fingerprint
   state). A `fingerprint_web_stack` action fans out from
   `web_target_identified` into per-technology recon states, and a
   `fingerprint_windows_network_services` action fans out from
   `network_target_identified` into SMB/domain-controller/print-spooler
   states for the Windows-network CVEs; Log4Shell skips fingerprinting
   entirely and is tried directly via blind JNDI injection, matching
   real-world practice. All confirmed-CVE states bridge into the same
   `low_priv_shell_obtained` (or, for the AD-focused chains, directly into
   higher-value domain-compromise) capability states the generic
   RCE-capable classes use.

4. **Hand-authored AI/LLM bridges** (`knowledge/graph/ai_bridges.json`): the
   9 OWASP LLM Top 10 (2025) classes -- prompt injection, excessive agency,
   insecure output handling, sensitive information disclosure, supply
   chain, data/model poisoning, system prompt leakage, vector/embedding
   weaknesses, unbounded consumption -- converge into the *exact same*
   capability states the web/app classes use, and add **zero new states**.
   A prompt injection that hijacks an over-scoped agent tool reaches
   `unauthorized_privileged_action_possible`, the same state IDOR or mass
   assignment reach; insecure output handling fans out directly into
   `xss_stored_confirmed` / `sqli_confirmed` / `command_injection_confirmed`
   depending on the downstream sink. This is deliberate: AI security isn't
   a separate graph bolted onto the side, it's the same attacker objectives
   reached through a model-mediated path.

Run `scripts/build_graph.py` to regenerate the merged output after editing
any of the four source files.

## Detection signals: authored hints, not a working classifier

Every state can carry `detection_signals` -- what you'd actually look for in
real tool output to recognize you've reached it:

```jsonc
{"state_id": "cloud_credentials_obtained", ...,
 "detection_signals": [{
   "signal_type": "http_response",
   "description": "The metadata/credentials endpoint returns a JSON object with access key / secret key / session token fields.",
   "examples": ["response body contains \"AccessKeyId\", \"SecretAccessKey\", \"Token\" (AWS)", "..."]
 }]}
```

This is a real gap being narrowed, not closed: these are still authored
judgment calls about what a signal looks like, not a working parser/regex an
agent can run unattended. What it adds over plain prose is a `signal_type`
(`http_response` / `timing` / `tool_output` / `file_system` / `network` /
`manual_judgment`) an agent can use to decide *how* to check -- inspect a
response, time a request, read a tool's output -- before it has any
target-specific detection logic of its own.

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

## Turning the static graph into training data: `scripts/simulate_graph.py`

A static graph is a prior, not evidence -- nobody has run it against a real
target. `simulate_graph.py` samples synthetic episodes from it: repeatedly
walk the graph from an entry state, sample which outcome occurs at each step
according to its `likelihood` (rare/possible/likely converted to sampling
weights), assign a shaped reward from the change in state `value` (+5 bonus
for reaching a `full_compromise` state), and log the full trajectory. This
does not create real signal about what works against real targets -- it's
still bootstrapped from the same authored judgments as the graph -- but it
is a materially different artifact: many diverse, complete (state, action,
outcome, reward) sequences, suitable as synthetic RL rollouts or a
policy-comparison sandbox, instead of one static structure.

```bash
python3 simulate_graph.py --episodes 3000 --policy random --out ../data/graph/episodes_random.jsonl
python3 simulate_graph.py --episodes 1000 --policy greedy --out ../data/graph/episodes_greedy.jsonl
python3 simulate_graph.py --episodes 1000 --policy epsilon_greedy --epsilon 0.2 --out ../data/graph/episodes_epsilon_greedy.jsonl
```

Three policies:
- **random** -- uniformly picks among available actions at each state.
- **greedy** -- picks the action maximizing Q(s,a) under a proper Bellman
  value function (`compute_value_function`, gamma=0.9, 200 value-iteration
  sweeps over the whole graph). A naive 1-step-lookahead greedy policy
  turned out to be statistically indistinguishable from random here: nearly
  every early-chain "recon" state has the same generic `value: "low"`, so
  1-ply expected value ties across almost all first moves. Value iteration
  looks past that flat first hop to where a chain actually leads.
- **epsilon_greedy** -- greedy with probability `1-epsilon` random exploration.

On the current graph (3000/1000/1000 episodes, seed 42): random reaches a
`full_compromise` state **6.7%** of the time, epsilon_greedy **14.4%**,
greedy **18.1%** -- a real, measurable gap that also sanity-checks the graph
itself (if greedy couldn't beat random, that would flag a bridge-chain gap).
The jump from the previous round's 5.3%/10.3%/13.1% tracks directly to the
CVE-chain expansion below: several of the new chains grant a high-value
capability state (domain admin, SYSTEM) in a single confirmed step, which
value iteration now correctly steers greedy toward.

Each episode:

```jsonc
{
  "policy": "greedy", "start_state": "web_target_identified",
  "steps": [
    {"t": 0, "state": "web_target_identified", "action_id": "log4j_jndi_injection_web",
     "outcome_id": "success", "to_state": "log4j_jndi_rce_confirmed", "likelihood": "rare", "reward": 4.0},
    {"t": 1, "state": "log4j_jndi_rce_confirmed", "action_id": "bridge_log4j_to_shell",
     "outcome_id": "success", "to_state": "low_priv_shell_obtained", "likelihood": "likely", "reward": 3.0},
    "..."
  ],
  "end_state": "full_host_compromise", "end_tier": "full_compromise",
  "total_reward": 21.0, "reached_goal": true, "terminated_reason": "terminal_state"
}
```

## Stats

293 states, 271 actions: 226 generated from the 44 vulnerability playbooks
(35 generic + 9 AI/LLM) plus 5 shared target-type entry states, 15 net-new
hand-authored generic-bridge states (21 defined, 6 are detection-signal
overrides of already-generated states) / 45 generic-bridge actions, 47
technology states / 37 technology actions covering 17 real CVEs, and 8
AI-bridge actions adding zero new states.

A 7-playbook blockchain/smart-contract domain (reentrancy, integer
overflow/underflow, access control, oracle manipulation, flash loan
attacks, unchecked external calls, front-running/MEV) was added on top of
this, contributing 36 new states and 28 new actions -- bringing the graph
to **329 states, 299 actions** in total. Validated with zero schema
errors, zero unreachable states (`scripts/validate_graph.py`).
