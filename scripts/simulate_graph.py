#!/usr/bin/env python3
"""Sample synthetic episodes (trajectories) from the attack graph.

The static graph is a prior, not evidence -- nobody has actually run it
against a target. This turns it into something an RL/behavior-cloning setup
can consume: repeatedly walk the graph from an entry state, sampling which
outcome occurs at each step according to its authored `likelihood` (rare /
possible / likely, converted to sampling weights below), assign a shaped
reward from the change in state `value`, and log the full trajectory.

This does NOT create real signal about what actually works against real
targets -- it's still bootstrapped from the same authored qualitative
judgments as the graph itself (see docs/GRAPH.md and DATA_LICENSE). What it
does provide: (a) many diverse, complete (state, action, outcome, reward)
sequences instead of one static structure, suitable as synthetic RL rollouts
or as a policy-comparison sandbox, and (b) a way to sanity-check the graph
itself -- e.g. if greedy-policy episodes almost never reach a goal, that's a
sign the bridge chains have a gap.

Usage:
    python3 simulate_graph.py --graph ../data/graph/attack_graph.json \
        --episodes 3000 --policy random --out ../data/graph/episodes_random.jsonl
    python3 simulate_graph.py --episodes 1000 --policy greedy --out ../data/graph/episodes_greedy.jsonl
    python3 simulate_graph.py --episodes 1000 --policy epsilon_greedy --epsilon 0.25 --out ../data/graph/episodes_epsilon_greedy.jsonl
"""
import argparse
import json
import random
import sys
from collections import Counter

VALUE_SCORE = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LIKELIHOOD_WEIGHT = {"rare": 0.15, "possible": 0.45, "likely": 0.85}
GOAL_BONUS = 5.0


def load_graph(path):
    with open(path) as f:
        graph = json.load(f)
    states_by_id = {s["state_id"]: s for s in graph["states"]}
    actions_by_from = {}
    for a in graph["actions"]:
        actions_by_from.setdefault(a["from_state"], []).append(a)
    return states_by_id, actions_by_from


def sample_outcome(rng, action):
    weights = [LIKELIHOOD_WEIGHT.get(o["likelihood"], 0.3) for o in action["outcomes"]]
    total = sum(weights)
    r = rng.random() * total
    upto = 0.0
    for o, w in zip(action["outcomes"], weights):
        upto += w
        if r <= upto:
            return o
    return action["outcomes"][-1]


def choose_action_random(rng, actions):
    return rng.choice(actions)


def edge_reward(states_by_id, from_state, to_state):
    r = VALUE_SCORE.get(states_by_id[to_state]["value"], 0) - VALUE_SCORE.get(states_by_id[from_state]["value"], 0)
    if states_by_id[to_state]["tier"] == "full_compromise":
        r += GOAL_BONUS
    return float(r)


def compute_value_function(states_by_id, actions_by_from, gamma=0.9, iterations=200):
    """Bellman value iteration over the graph, so a 'greedy' policy can see past
    the immediate hop (most single-class recon steps look identical 1-ply out --
    they only differentiate once you look several hops ahead toward a goal)."""
    V = {sid: float(VALUE_SCORE.get(s["value"], 0)) + (GOAL_BONUS if s["tier"] == "full_compromise" else 0.0) for sid, s in states_by_id.items()}
    for _ in range(iterations):
        new_V = dict(V)
        for sid in states_by_id:
            actions = actions_by_from.get(sid, [])
            if not actions:
                continue  # terminal: V stays at its intrinsic value
            best_q = None
            for a in actions:
                weights = [LIKELIHOOD_WEIGHT.get(o["likelihood"], 0.3) for o in a["outcomes"]]
                total = sum(weights) or 1.0
                q = sum(
                    (w / total) * (edge_reward(states_by_id, sid, o["to_state"]) + gamma * V[o["to_state"]])
                    for o, w in zip(a["outcomes"], weights)
                )
                if best_q is None or q > best_q:
                    best_q = q
            new_V[sid] = best_q
        V = new_V
    return V


def q_value(states_by_id, V, gamma, from_state, action):
    weights = [LIKELIHOOD_WEIGHT.get(o["likelihood"], 0.3) for o in action["outcomes"]]
    total = sum(weights) or 1.0
    return sum(
        (w / total) * (edge_reward(states_by_id, from_state, o["to_state"]) + gamma * V[o["to_state"]])
        for o, w in zip(action["outcomes"], weights)
    )


def choose_action_greedy(rng, actions, states_by_id, cur_state, V, gamma):
    scored = [(q_value(states_by_id, V, gamma, cur_state, a), a) for a in actions]
    best = max(s for s, _ in scored)
    top = [a for s, a in scored if abs(s - best) < 1e-9]
    return rng.choice(top)


def choose_action(rng, actions, states_by_id, cur_state, policy, epsilon, V, gamma):
    if policy == "random":
        return choose_action_random(rng, actions)
    if policy == "greedy":
        return choose_action_greedy(rng, actions, states_by_id, cur_state, V, gamma)
    if policy == "epsilon_greedy":
        if rng.random() < epsilon:
            return choose_action_random(rng, actions)
        return choose_action_greedy(rng, actions, states_by_id, cur_state, V, gamma)
    raise ValueError(policy)


def run_episode(rng, states_by_id, actions_by_from, entry_states, policy, epsilon, max_steps, max_state_visits, V, gamma):
    start = rng.choice(entry_states)
    cur = start
    steps = []
    total_reward = 0.0
    visit_counts = Counter([cur])
    terminated_reason = "max_steps"

    for t in range(max_steps):
        actions = actions_by_from.get(cur, [])
        if not actions:
            terminated_reason = "terminal_state"
            break
        action = choose_action(rng, actions, states_by_id, cur, policy, epsilon, V, gamma)
        outcome = sample_outcome(rng, action)
        to_state = outcome["to_state"]
        reward = edge_reward(states_by_id, cur, to_state)

        steps.append({
            "t": t,
            "state": cur,
            "action_id": action["action_id"],
            "action": action["action"],
            "is_bridge": bool(action.get("is_bridge")),
            "outcome_id": outcome["outcome_id"],
            "observation": outcome["observation"],
            "likelihood": outcome["likelihood"],
            "to_state": to_state,
            "reward": reward,
        })
        total_reward += reward
        cur = to_state
        visit_counts[cur] += 1
        if visit_counts[cur] > max_state_visits:
            terminated_reason = "loop_cap"
            break
    else:
        terminated_reason = "max_steps"

    end_state = states_by_id[cur]
    return {
        "policy": policy,
        "start_state": start,
        "steps": steps,
        "end_state": cur,
        "end_tier": end_state["tier"],
        "end_value": end_state["value"],
        "total_reward": round(total_reward, 2),
        "reached_goal": end_state["tier"] == "full_compromise",
        "terminated_reason": terminated_reason,
        "n_steps": len(steps),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default="../data/graph/attack_graph.json")
    ap.add_argument("--episodes", type=int, default=1000)
    ap.add_argument("--policy", choices=["random", "greedy", "epsilon_greedy"], default="random")
    ap.add_argument("--epsilon", type=float, default=0.2)
    ap.add_argument("--max-steps", type=int, default=25)
    ap.add_argument("--max-state-visits", type=int, default=3, help="loop cap: max times a single state may recur in one episode")
    ap.add_argument("--start", default=None, help="fix the entry state instead of sampling uniformly among entry states")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--gamma", type=float, default=0.9, help="discount factor for the greedy policy's value function")
    ap.add_argument("--vi-iterations", type=int, default=200, help="value-iteration sweeps for the greedy policy")
    ap.add_argument("--out", default="../data/graph/episodes.jsonl")
    args = ap.parse_args()

    states_by_id, actions_by_from = load_graph(args.graph)
    entry_states = [args.start] if args.start else sorted(s["state_id"] for s in states_by_id.values() if s["tier"] == "entry")
    if args.start and args.start not in states_by_id:
        print(f"Unknown --start state: {args.start}", file=sys.stderr)
        sys.exit(2)

    V = {}
    if args.policy in ("greedy", "epsilon_greedy"):
        V = compute_value_function(states_by_id, actions_by_from, args.gamma, args.vi_iterations)

    rng = random.Random(args.seed)
    reached_goal = 0
    total_reward_sum = 0.0
    total_len_sum = 0
    end_tier_counts = Counter()

    with open(args.out, "w") as f:
        for i in range(args.episodes):
            ep = run_episode(rng, states_by_id, actions_by_from, entry_states, args.policy, args.epsilon, args.max_steps, args.max_state_visits, V, args.gamma)
            ep["episode_id"] = f"{args.policy}_{i:06d}"
            f.write(json.dumps(ep, ensure_ascii=False) + "\n")
            reached_goal += ep["reached_goal"]
            total_reward_sum += ep["total_reward"]
            total_len_sum += ep["n_steps"]
            end_tier_counts[ep["end_tier"]] += 1

    n = args.episodes
    print(f"policy={args.policy} episodes={n} goal_reach_rate={reached_goal/n:.1%} avg_reward={total_reward_sum/n:.2f} avg_len={total_len_sum/n:.1f}", file=sys.stderr)
    print(f"end_tier distribution: {dict(end_tier_counts)}", file=sys.stderr)
    print(f"Wrote {n} episodes to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
