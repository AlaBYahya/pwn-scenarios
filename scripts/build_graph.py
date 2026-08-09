#!/usr/bin/env python3
"""Build the unified attack decision graph.

Mechanically converts each vulnerability_playbooks.json entry's linear
`process` steps into a small branching chain:

    {target_type}_target_identified
        --step1--> success -> {id}_after_step1   | failure -> {id}_ruled_out
        --step2--> success -> {id}_after_step2   | failure -> {id}_ruled_out
        ...
        --stepN--> success -> {id}_confirmed      | failure -> {id}_ruled_out

Then merges in knowledge/graph/bridges.json -- the hand-authored states and
actions that connect each class's `{id}_confirmed` state into a shared
cross-class vocabulary of capability/privileged_access/full_compromise
states (e.g. multiple RCE-capable classes converge on
`low_priv_shell_obtained`, which chains toward `full_host_compromise`).
This is the part that turns 35 separate linear playbooks into one graph an
agent can actually search over for multi-step attack paths.

`ctf_challenge_generic` and `tryhackme_room_generic` are meta-playbooks (not
a specific vulnerability class) and are excluded from graph generation.

Usage:
    python3 build_graph.py --playbooks ../knowledge/vulnerability_playbooks.json \
        --bridges ../knowledge/graph/bridges.json --out ../data/graph/attack_graph.json
"""
import argparse
import json
import sys

SCHEMA_VERSION = "1.0.0"

EXCLUDED_PLAYBOOKS = {"ctf_challenge_generic", "tryhackme_room_generic", "hackthebox_box_generic"}

# Heuristic "how valuable is confirming this vulnerability class, on its own"
# -- authored security judgment, not a measured score. See DATA_LICENSE.
CONFIRMED_VALUE = {
    "rce_generic": "critical", "command_injection": "critical", "insecure_deserialization": "critical",
    "ssti": "critical", "sqli": "critical", "unrestricted_file_upload": "critical",
    "idor": "high", "xss_stored": "high", "ssrf": "high", "auth_bypass": "high",
    "broken_access_control": "high", "account_takeover": "high", "jwt_vulnerabilities": "high",
    "subdomain_takeover": "high", "xxe": "high", "mass_assignment": "high",
    "path_traversal": "high", "http_request_smuggling": "high", "memory_corruption": "high",
    "xss_reflected": "medium", "xss_dom": "medium", "csrf": "medium", "open_redirect": "medium",
    "oauth_misconfiguration": "medium", "cors_misconfiguration": "medium", "race_condition": "medium",
    "business_logic_flaw": "medium", "cache_poisoning": "medium", "clickjacking": "medium",
    "graphql_abuse": "medium", "prototype_pollution": "medium", "2fa_bypass": "medium",
    "information_disclosure": "medium", "hardcoded_secrets": "medium", "dos": "medium",
    "prompt_injection": "high", "excessive_agency": "high", "insecure_output_handling": "high",
    "sensitive_information_disclosure_llm": "high", "llm_supply_chain": "high",
    "system_prompt_leakage": "medium", "rag_embedding_weaknesses": "medium",
    "training_data_poisoning": "medium", "model_denial_of_service": "medium",
}


HTTP_TOOLS = {"burp suite", "burp repeater", "burp intruder", "burp collaborator", "curl", "browser", "ffuf", "postman", "fetch api"}
TOOL_OUTPUT_TOOLS = {
    "gdb", "pwntools", "valgrind", "addresssanitizer", "afl++", "libfuzzer", "honggfuzz", "ida", "ghidra",
    "linpeas", "winpeas", "enum4linux", "sqlmap", "jwt_tool", "tplmap", "hashcat", "trufflehog", "gitleaks",
    "aws-cli", "pacu", "scoutsuite",
}


def classify_signal_type(tools, action_text, observation_text):
    tools_lower = {t.lower() for t in (tools or [])}
    text = f"{action_text} {observation_text}".lower()
    if any(t in TOOL_OUTPUT_TOOLS for t in tools_lower):
        return "tool_output"
    if "time" in text or "sleep" in text or "delay" in text or "timing" in text:
        return "timing"
    if tools_lower & HTTP_TOOLS:
        return "http_response"
    return "manual_judgment"


def build_per_class(playbooks):
    states, actions = {}, {}
    target_types_seen = set()

    for pb in playbooks:
        pb_id = pb["playbook_id"]
        if pb_id in EXCLUDED_PLAYBOOKS:
            continue
        target_type = pb["default_target_type"]
        target_types_seen.add(target_type)
        entry_state = f"{target_type}_target_identified"

        process = pb["process"]
        n_steps = len(process)
        ruled_out_id = f"{pb_id}_ruled_out"
        states[ruled_out_id] = {
            "state_id": ruled_out_id,
            "description": f"{pb['vulnerability_class']} was not confirmed via the attempted path on this target.",
            "tier": "ruled_out",
            "value": "none",
            "target_types": [target_type],
            "playbook_ref": pb_id,
            "detection_signals": [{
                "signal_type": "manual_judgment",
                "description": "Expected result absent across the attempted variations of this technique.",
            }],
        }

        prev_state = entry_state
        for i, step in enumerate(process, start=1):
            is_last = i == n_steps
            signal_type = classify_signal_type(step.get("tools"), step["action"], step["expected_observation"])
            success_state_id = f"{pb_id}_confirmed" if is_last else f"{pb_id}_after_step{i}"
            if success_state_id not in states:
                if is_last:
                    states[success_state_id] = {
                        "state_id": success_state_id,
                        "description": f"{pb['vulnerability_class']} confirmed exploitable.",
                        "tier": "vulnerability_confirmed",
                        "value": CONFIRMED_VALUE.get(pb_id, "medium"),
                        "target_types": [target_type],
                        "playbook_ref": pb_id,
                        "detection_signals": [{
                            "signal_type": signal_type,
                            "description": step["expected_observation"],
                        }],
                    }
                else:
                    states[success_state_id] = {
                        "state_id": success_state_id,
                        "description": f"Step {i} of {pb['vulnerability_class']} testing succeeded: {step['expected_observation']}",
                        "tier": "recon",
                        "value": "low",
                        "target_types": [target_type],
                        "playbook_ref": pb_id,
                        "detection_signals": [{
                            "signal_type": signal_type,
                            "description": step["expected_observation"],
                        }],
                    }

            action_id = f"{pb_id}_step{i}"
            actions[action_id] = {
                "action_id": action_id,
                "from_state": prev_state,
                "action": step["action"],
                "technique": step.get("technique"),
                "tools": step.get("tools", []),
                "playbook_ref": pb_id,
                "is_bridge": False,
                "outcomes": [
                    {
                        "outcome_id": "success",
                        "observation": step["expected_observation"],
                        "likelihood": "possible",
                        "to_state": success_state_id,
                        "note": None,
                    },
                    {
                        "outcome_id": "failure",
                        "observation": f"Expected result not observed ({step['expected_observation']!r} did not occur).",
                        "likelihood": "possible",
                        "to_state": ruled_out_id,
                        "note": "Pivot: try a different parameter/endpoint for this technique, or move to another vulnerability class from the entry state.",
                    },
                ],
            }
            prev_state = success_state_id

    for t in target_types_seen:
        sid = f"{t}_target_identified"
        states[sid] = {
            "state_id": sid,
            "description": f"A {t} target has been identified and is in scope for testing.",
            "tier": "entry",
            "value": "none",
            "target_types": [t],
            "playbook_ref": None,
            "detection_signals": [{
                "signal_type": "manual_judgment",
                "description": "Target is confirmed in-scope and reachable (rules of engagement / scope document).",
            }],
        }

    return states, actions


def merge_bridges(states, actions, bridges):
    for s in bridges.get("states", []):
        if s["state_id"] in states:
            print(f"WARNING: bridge state {s['state_id']} collides with a generated state; bridge wins", file=sys.stderr)
        states[s["state_id"]] = s
    for a in bridges.get("actions", []):
        a = dict(a)
        a["is_bridge"] = True
        if a["action_id"] in actions:
            print(f"WARNING: bridge action {a['action_id']} collides with a generated action; bridge wins", file=sys.stderr)
        actions[a["action_id"]] = a
    return states, actions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--playbooks", default="../knowledge/vulnerability_playbooks.json")
    ap.add_argument("--bridges", default="../knowledge/graph/bridges.json")
    ap.add_argument("--tech-bridges", default="../knowledge/graph/technology_bridges.json")
    ap.add_argument("--ai-bridges", default="../knowledge/graph/ai_bridges.json")
    ap.add_argument("--out", default="../data/graph/attack_graph.json")
    args = ap.parse_args()

    with open(args.playbooks) as f:
        playbooks = json.load(f)
    with open(args.bridges) as f:
        bridges = json.load(f)
    with open(args.tech_bridges) as f:
        tech_bridges = json.load(f)
    with open(args.ai_bridges) as f:
        ai_bridges = json.load(f)

    states, actions = build_per_class(playbooks)
    states, actions = merge_bridges(states, actions, bridges)
    states, actions = merge_bridges(states, actions, tech_bridges)
    states, actions = merge_bridges(states, actions, ai_bridges)

    graph = {
        "schema_version": SCHEMA_VERSION,
        "states": sorted(states.values(), key=lambda s: s["state_id"]),
        "actions": sorted(actions.values(), key=lambda a: a["action_id"]),
    }

    import os
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(graph['states'])} states and {len(graph['actions'])} actions to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
