#!/usr/bin/env python3
"""Validate the attack graph: schema conformance, referential integrity
(every from_state/to_state must exist), and reachability from entry states.

Usage:
    python3 validate_graph.py --graph ../data/graph/attack_graph.json --schema ../schema/graph.schema.json
"""
import argparse
import json
import sys

import jsonschema


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default="../data/graph/attack_graph.json")
    ap.add_argument("--schema", default="../schema/graph.schema.json")
    args = ap.parse_args()

    with open(args.graph) as f:
        graph = json.load(f)
    with open(args.schema) as f:
        schema = json.load(f)

    validator = jsonschema.Draft7Validator(schema)
    errors = 0
    for err in validator.iter_errors(graph):
        errors += 1
        print(f"schema error: {err.message} (path: {list(err.path)})", file=sys.stderr)

    state_ids = {s["state_id"] for s in graph["states"]}
    if len(state_ids) != len(graph["states"]):
        errors += 1
        print("duplicate state_id detected", file=sys.stderr)

    action_ids = {a["action_id"] for a in graph["actions"]}
    if len(action_ids) != len(graph["actions"]):
        errors += 1
        print("duplicate action_id detected", file=sys.stderr)

    for a in graph["actions"]:
        if a["from_state"] not in state_ids:
            errors += 1
            print(f"action {a['action_id']}: from_state {a['from_state']!r} does not exist", file=sys.stderr)
        for o in a["outcomes"]:
            if o["to_state"] not in state_ids:
                errors += 1
                print(f"action {a['action_id']} outcome {o['outcome_id']}: to_state {o['to_state']!r} does not exist", file=sys.stderr)

    # Reachability from entry states (BFS over the directed graph).
    entry_states = {s["state_id"] for s in graph["states"] if s["tier"] == "entry"}
    adj = {}
    for a in graph["actions"]:
        adj.setdefault(a["from_state"], []).extend(o["to_state"] for o in a["outcomes"])

    visited = set(entry_states)
    frontier = list(entry_states)
    while frontier:
        cur = frontier.pop()
        for nxt in adj.get(cur, []):
            if nxt not in visited:
                visited.add(nxt)
                frontier.append(nxt)

    unreachable = state_ids - visited
    if unreachable:
        print(f"WARNING: {len(unreachable)} state(s) unreachable from any entry state: {sorted(unreachable)}", file=sys.stderr)

    print(f"Validated {len(graph['states'])} states, {len(graph['actions'])} actions: {errors} error(s), {len(unreachable)} unreachable state(s)", file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
