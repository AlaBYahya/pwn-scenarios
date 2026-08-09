#!/usr/bin/env python3
"""Traverse and search the attack graph -- the "what's my next move, and
where might it lead" tool the graph exists to support.

Examples:
    # What are my candidate first moves from a fresh web target?
    python3 query_graph.py --from web_target_identified

    # Look 2 moves ahead (like a shallow chess move tree)
    python3 query_graph.py --from web_target_identified --depth 2

    # Inspect a specific state: what leads to it, what leads out of it
    python3 query_graph.py --state idor_confirmed

    # Find a strong path from a fresh web target to full application compromise
    python3 query_graph.py --best-path --from web_target_identified --to full_application_compromise

Run with no arguments to list entry states and the tier/value legend.

Path search caveat: `--best-path` is a greedy best-first search over
cumulative (value x likelihood) score, bounded by --max-expansions and
--max-depth. It is a practical heuristic search, NOT a guaranteed-optimal
solver -- value/likelihood are authored qualitative judgments, not measured
probabilities. Treat the returned path as "a strong candidate," not "the
provably best attack path."
"""
import argparse
import heapq
import json
import sys

VALUE_SCORE = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LIKELIHOOD_SCORE = {"rare": 1, "possible": 2, "likely": 3}


def load_graph(path):
    with open(path) as f:
        graph = json.load(f)
    states_by_id = {s["state_id"]: s for s in graph["states"]}
    actions_by_from = {}
    for a in graph["actions"]:
        actions_by_from.setdefault(a["from_state"], []).append(a)
    actions_by_to = {}
    for a in graph["actions"]:
        for o in a["outcomes"]:
            actions_by_to.setdefault(o["to_state"], []).append((a, o))
    return graph, states_by_id, actions_by_from, actions_by_to


def fmt_state(states_by_id, state_id):
    s = states_by_id.get(state_id)
    if not s:
        return state_id
    return f"{state_id} [{s['tier']}/{s['value']}]"


def cmd_overview(graph, states_by_id):
    entry = [s for s in graph["states"] if s["tier"] == "entry"]
    print("Entry states (start here):", file=sys.stderr)
    for s in sorted(entry, key=lambda s: s["state_id"]):
        print(f"  {s['state_id']}: {s['description']}", file=sys.stderr)
    print("\nTiers (kill-chain position): entry -> recon -> vulnerability_confirmed -> capability -> privileged_access -> full_compromise (ruled_out = dead end)", file=sys.stderr)
    print("Values (heuristic worth of the state, like a chess position eval): none < low < medium < high < critical", file=sys.stderr)
    print(f"\n{len(graph['states'])} states, {len(graph['actions'])} actions total. Use --from <state_id> to see candidate moves.", file=sys.stderr)


def cmd_from(states_by_id, actions_by_from, state_id, depth, visited=None, indent=0):
    if state_id not in states_by_id:
        print(f"Unknown state: {state_id}", file=sys.stderr)
        return
    if indent == 0:
        print(f"From {fmt_state(states_by_id, state_id)}:")
    visited = (visited or set()) | {state_id}
    actions = actions_by_from.get(state_id, [])
    if not actions:
        print("  " * (indent + 1) + "(terminal -- no further actions defined)")
        return
    for a in actions:
        pad = "  " * (indent + 1)
        tools = f" [{', '.join(a['tools'])}]" if a.get("tools") else ""
        bridge = " (bridge)" if a.get("is_bridge") else ""
        print(f"{pad}- {a['action_id']}{bridge}: {a['action']}{tools}")
        for o in a["outcomes"]:
            opad = "  " * (indent + 2)
            print(f"{opad}-> ({o['likelihood']}) {fmt_state(states_by_id, o['to_state'])}: {o['observation']}")
            if o.get("note"):
                print(f"{opad}   note: {o['note']}")
            if depth > 1 and o["to_state"] not in visited:
                cmd_from(states_by_id, actions_by_from, o["to_state"], depth - 1, visited, indent + 3)


def cmd_state(states_by_id, actions_by_from, actions_by_to, state_id):
    if state_id not in states_by_id:
        print(f"Unknown state: {state_id}", file=sys.stderr)
        return
    s = states_by_id[state_id]
    print(json.dumps(s, indent=2))
    print(f"\nIncoming ({len(actions_by_to.get(state_id, []))}):")
    for a, o in actions_by_to.get(state_id, []):
        print(f"  {fmt_state(states_by_id, a['from_state'])} --[{a['action_id']}: {a['action']}]--> ({o['likelihood']})")
    print(f"\nOutgoing ({len(actions_by_from.get(state_id, []))}):")
    for a in actions_by_from.get(state_id, []):
        for o in a["outcomes"]:
            print(f"  --[{a['action_id']}: {a['action']}]--> ({o['likelihood']}) {fmt_state(states_by_id, o['to_state'])}")


def best_path(states_by_id, actions_by_from, start, goal, max_expansions, max_depth):
    if start not in states_by_id or goal not in states_by_id:
        return None
    tie = 0
    heap = [(0.0, tie, start, (start,), [])]
    expansions = 0
    while heap:
        neg_score, _, cur, path_states, path_actions = heapq.heappop(heap)
        score = -neg_score
        if cur == goal:
            return score, path_states, path_actions
        expansions += 1
        if expansions > max_expansions or len(path_states) > max_depth:
            continue
        for a in actions_by_from.get(cur, []):
            for o in a["outcomes"]:
                nxt = o["to_state"]
                if nxt in path_states:
                    continue
                edge_score = VALUE_SCORE.get(states_by_id[nxt]["value"], 0) * LIKELIHOOD_SCORE.get(o["likelihood"], 1)
                tie += 1
                heapq.heappush(heap, (-(score + edge_score), tie, nxt, path_states + (nxt,), path_actions + [(a, o)]))
    return None


def cmd_best_path(states_by_id, actions_by_from, start, goal, max_expansions, max_depth):
    result = best_path(states_by_id, actions_by_from, start, goal, max_expansions, max_depth)
    if not result:
        print(f"No path found from {start} to {goal} within max_depth={max_depth}/max_expansions={max_expansions}.", file=sys.stderr)
        return
    score, path_states, path_actions = result
    print(f"Path found, cumulative heuristic score = {score:.1f} ({len(path_actions)} hops)\n")
    print(fmt_state(states_by_id, path_states[0]))
    for (a, o), st in zip(path_actions, path_states[1:]):
        bridge = " (bridge)" if a.get("is_bridge") else ""
        print(f"  --[{a['action_id']}{bridge}: {a['action']}]--> ({o['likelihood']})")
        print(f"{fmt_state(states_by_id, st)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", default="../data/graph/attack_graph.json")
    ap.add_argument("--from", dest="from_state", help="show candidate actions/outcomes from this state")
    ap.add_argument("--depth", type=int, default=1, help="lookahead depth for --from (default 1)")
    ap.add_argument("--state", help="show full detail (incoming + outgoing) for a state")
    ap.add_argument("--best-path", action="store_true", help="search for a strong path from --from to --to")
    ap.add_argument("--to", help="goal state_id for --best-path")
    ap.add_argument("--max-expansions", type=int, default=50000)
    ap.add_argument("--max-depth", type=int, default=15)
    args = ap.parse_args()

    graph, states_by_id, actions_by_from, actions_by_to = load_graph(args.graph)

    if args.best_path:
        if not args.from_state or not args.to:
            print("--best-path requires both --from and --to", file=sys.stderr)
            sys.exit(2)
        cmd_best_path(states_by_id, actions_by_from, args.from_state, args.to, args.max_expansions, args.max_depth)
    elif args.state:
        cmd_state(states_by_id, actions_by_from, actions_by_to, args.state)
    elif args.from_state:
        cmd_from(states_by_id, actions_by_from, args.from_state, args.depth)
    else:
        cmd_overview(graph, states_by_id)


if __name__ == "__main__":
    main()
