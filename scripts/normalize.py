#!/usr/bin/env python3
"""Normalize raw collected records into the unified scenario schema.

For each raw record (from HackerOne, Pentester Land, or CTF collectors), this:
  1. Classifies it against a playbook in knowledge/vulnerability_playbooks.json
     using alias/keyword matching against title + weakness/bug tags.
  2. Builds a self-contained scenario record: the playbook's generic
     conditions/process/impact/remediation, plus this instance's own
     source metadata (title, url, program, date, severity).
  3. Assigns a stable id and writes one JSON object per line to the output.

Records that cannot be matched to any playbook with reasonable confidence are
skipped (logged to stderr) rather than emitted with empty scenario content.

Usage:
    python3 normalize.py --raw-dir ../data/raw --out ../data/scenarios/scenarios.jsonl
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0.0"
LICENSE_NOTE = (
    "This record contains normalized classification data and a generic "
    "remediation/process playbook, plus a link back to the original source. "
    "It does not reproduce the original writeup's text. See DATA_LICENSE for terms."
)


def load_playbooks(path):
    with open(path) as f:
        playbooks = json.load(f)
    by_id = {p["playbook_id"]: p for p in playbooks}
    # Build a flat list of (alias, playbook_id) sorted by alias length descending
    # so longer, more specific aliases are checked before short generic ones.
    alias_map = []
    for p in playbooks:
        for alias in p["aliases"]:
            alias_map.append((alias.lower(), p["playbook_id"]))
    alias_map.sort(key=lambda t: -len(t[0]))
    return by_id, alias_map


def classify(text_fields, alias_map):
    """Match a list of text fields against playbook aliases. Returns (playbook_id, confidence) or (None, None)."""
    haystack = " ".join(t for t in text_fields if t).lower()
    if not haystack.strip():
        return None, None
    matches = []
    for alias, playbook_id in alias_map:
        # word-boundary match to avoid e.g. "sso" matching inside another word
        pattern = r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])"
        if re.search(pattern, haystack):
            matches.append((alias, playbook_id))
    if not matches:
        return None, None
    # Highest confidence: exact alias match on a short, dedicated tag field is
    # handled by the caller passing tags separately; here we just take the
    # longest (most specific) alias match.
    best_alias, best_id = matches[0]
    confidence = "high" if len(matches) == 1 or len(best_alias) > 12 else "medium"
    return best_id, confidence


def make_id(platform, url):
    h = hashlib.sha256(f"{platform}|{url}".encode()).hexdigest()
    return h[:16]


def clean_list(values):
    """Drop Pentester Land's '-' empty-field placeholder and blank strings."""
    return [v.strip() for v in values if v and v.strip() and v.strip() != "-"]


def severity_normalize(raw):
    if not raw:
        return "unknown"
    raw = raw.lower()
    if raw in ("none", "unknown", ""):
        return "unknown"
    if raw in ("low", "medium", "high", "critical"):
        return raw
    return "unknown"


def build_record(raw, playbook_id, confidence, playbooks_by_id, collector_name):
    pb = playbooks_by_id[playbook_id]
    platform = raw["source_platform"]
    url = raw["url"]

    if platform == "hackerone":
        title = raw.get("title") or pb["vulnerability_class"]
        severity = severity_normalize(raw.get("severity"))
        program = raw.get("program")
        author = None
        disclosed_at = raw.get("disclosed_at")
        if disclosed_at:
            disclosed_at = disclosed_at[:10]
        bounty = None
        tags = [t for t in [raw.get("weakness")] if t]
        summary = f"{pb['vulnerability_class']} reported against {program or 'a public bug bounty program'}."
    elif platform == "aggregated_writeup":
        title = raw.get("title") or pb["vulnerability_class"]
        severity = "unknown"
        programs = clean_list(raw.get("programs") or [])
        program = ", ".join(programs) if programs else None
        authors = clean_list(raw.get("authors") or [])
        author = ", ".join(authors) if authors else None
        disclosed_at = raw.get("publication_date")
        bounty = raw.get("bounty") if raw.get("bounty") not in (None, "-", "") else None
        tags = raw.get("bugs") or []
        summary = f"{pb['vulnerability_class']} writeup" + (f" against {program}" if program else "") + "."
    elif platform == "ctf":
        title = raw.get("title") or pb["vulnerability_class"]
        severity = "unknown"
        program = None
        author = None
        disclosed_at = None
        bounty = None
        tags = ["ctf", raw.get("topic_matched")]
        stars = raw.get("stars")
        summary = f"Curated CTF writeup collection ({stars} stars on GitHub): {raw.get('description') or title}."
    else:
        raise ValueError(f"unknown platform {platform}")

    record = {
        "id": make_id(platform, url),
        "schema_version": SCHEMA_VERSION,
        "title": title,
        "vulnerability": {
            "class": pb["vulnerability_class"],
            "cwe": pb["cwe"],
            "owasp_category": pb["owasp_category"],
            "severity": severity,
        },
        "target": {
            "type": pb["default_target_type"],
            "technology_hints": [],
        },
        "scenario": {
            "summary": summary,
            "preconditions": pb["preconditions"],
            "process": pb["process"],
            "decision_points": pb.get("decision_points", []),
            "impact": pb["impact"],
            "remediation": pb["remediation"],
        },
        "provenance": {
            "playbook_id": playbook_id,
            "grounded_instance": True,
            "confidence": confidence,
        },
        "source": {
            "platform": platform,
            "url": url,
            "program": program,
            "author": author,
            "disclosed_at": disclosed_at,
            "bounty": bounty,
        },
        "tags": sorted(set(t for t in tags if t)),
        "collection_metadata": {
            "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collector": collector_name,
        },
        "license_note": LICENSE_NOTE,
    }
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", default="../data/raw")
    ap.add_argument("--playbooks", default="../knowledge/vulnerability_playbooks.json")
    ap.add_argument("--out", default="../data/scenarios/scenarios.jsonl")
    ap.add_argument("--max-per-source", type=int, default=0, help="0 = no cap")
    args = ap.parse_args()

    playbooks_by_id, alias_map = load_playbooks(args.playbooks)

    seen_ids = set()
    total_in, total_out, total_skipped = 0, 0, 0
    skip_reasons = {}

    with open(args.out, "w") as out_f:
        for raw_path in sorted(glob.glob(os.path.join(args.raw_dir, "*.jsonl"))):
            collector_name = os.path.basename(raw_path)
            count_this_source = 0
            with open(raw_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    total_in += 1
                    raw = json.loads(line)
                    platform = raw["source_platform"]

                    if platform == "hackerone":
                        text_fields = [raw.get("weakness"), raw.get("title")]
                        tag_field = raw.get("weakness")
                    elif platform == "aggregated_writeup":
                        text_fields = (raw.get("bugs") or []) + [raw.get("title")]
                        tag_field = " ".join(raw.get("bugs") or [])
                    elif platform == "ctf":
                        text_fields = ["ctf writeups"]
                        tag_field = "ctf"
                    else:
                        continue

                    # Prefer classifying on the dedicated tag field first (higher signal),
                    # fall back to full text fields.
                    playbook_id, confidence = classify([tag_field], alias_map)
                    if not playbook_id:
                        playbook_id, confidence = classify(text_fields, alias_map)
                        if playbook_id:
                            confidence = "low"

                    if not playbook_id:
                        total_skipped += 1
                        skip_reasons[platform] = skip_reasons.get(platform, 0) + 1
                        continue

                    if args.max_per_source and count_this_source >= args.max_per_source:
                        continue

                    record = build_record(raw, playbook_id, confidence, playbooks_by_id, collector_name)
                    if record["id"] in seen_ids:
                        continue
                    seen_ids.add(record["id"])

                    out_f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    total_out += 1
                    count_this_source += 1

    print(f"Read {total_in} raw records, wrote {total_out} scenarios, skipped {total_skipped} (unclassified)", file=sys.stderr)
    print(f"Skip breakdown by source: {skip_reasons}", file=sys.stderr)


if __name__ == "__main__":
    main()
