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


def build_cwe_index(playbooks_by_id):
    """Map each CWE string to the playbook_id(s) that declare it, e.g. multiple
    playbooks can legitimately share a CWE (CWE-287 covers auth_bypass,
    account_takeover, oauth_misconfiguration, 2fa_bypass alike)."""
    index = {}
    for pid, pb in playbooks_by_id.items():
        cwe = pb.get("cwe")
        if cwe:
            index.setdefault(cwe, []).append(pid)
    return index


def classify_by_cwe(cwe_ids, title_text, cwe_index, alias_map):
    """Classify a record with known, real CWE ID(s) (e.g. from GHSA) against
    playbooks declaring that CWE. Far higher precision than keyword matching
    since the CWE is authoritative, not inferred from a headline.
    Returns (playbook_id, confidence) or (None, None)."""
    candidates = []
    for cwe in cwe_ids or []:
        candidates.extend(cwe_index.get(cwe, []))
    candidates = list(dict.fromkeys(candidates))  # dedupe, preserve order
    if not candidates:
        return None, None
    if len(candidates) == 1:
        return candidates[0], "high"
    # Multiple playbooks share this CWE (e.g. several auth-related classes on
    # CWE-287) -- disambiguate using the title against only those candidates'
    # aliases. Agreement between a real CWE and a keyword match is strong.
    restricted_aliases = [(alias, pid) for alias, pid in alias_map if pid in candidates]
    pid, _ = classify([title_text], restricted_aliases)
    if pid:
        return pid, "high"
    return candidates[0], "medium"


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
        tags = ["ctf"]
        summary = f"CTF writeup ('{title}') covering {pb['vulnerability_class']}."
    elif platform == "tryhackme":
        title = raw.get("title") or pb["vulnerability_class"]
        severity = "unknown"
        program = "TryHackMe"
        author = None
        disclosed_at = None
        bounty = None
        stars = raw.get("repo_stars")
        tags = ["tryhackme"]
        summary = f"TryHackMe room writeup ('{title}') covering {pb['vulnerability_class']}."
    elif platform == "hackthebox":
        title = raw.get("title") or pb["vulnerability_class"]
        severity = "unknown"
        program = "HackTheBox"
        author = None
        disclosed_at = None
        bounty = None
        stars = raw.get("repo_stars")
        tags = ["hackthebox"]
        summary = f"HackTheBox machine writeup ('{title}') covering {pb['vulnerability_class']}."
    elif platform == "ghsa":
        title = raw.get("title") or pb["vulnerability_class"]
        severity = severity_normalize(raw.get("severity"))
        program = raw.get("package") or raw.get("ecosystem")
        author = None
        disclosed_at = raw.get("disclosed_at")
        if disclosed_at:
            disclosed_at = disclosed_at[:10]
        bounty = None
        tags = [t for t in [raw.get("ecosystem"), raw.get("cve_id")] if t]
        pkg_bit = f" in {program}" if program else ""
        summary = f"{pb['vulnerability_class']} (GitHub Security Advisory {raw.get('ghsa_id')}){pkg_bit}."
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
    ap.add_argument(
        "--existing",
        default=None,
        help=(
            "Path to an already-normalized scenarios.jsonl to merge new records on top "
            "of, instead of rebuilding from --raw-dir alone. Use this when --raw-dir only "
            "contains a partial/incremental set of sources (e.g. the daily RSS+blogs job) "
            "-- without it, the output would only ever contain today's raw-dir sources and "
            "silently drop everything from sources not re-collected this run."
        ),
    )
    args = ap.parse_args()

    playbooks_by_id, alias_map = load_playbooks(args.playbooks)
    cwe_index = build_cwe_index(playbooks_by_id)

    seen_ids = set()
    seen_urls = set()
    total_in, total_out, total_skipped, total_cross_platform_dupes = 0, 0, 0, 0
    total_existing = 0
    skip_reasons = {}

    # Process the most structured/authoritative source for a given real-world
    # writeup first, so cross-platform URL overlap (e.g. Pentester Land linking
    # to a HackerOne report we already collected directly) resolves in favor
    # of the more precisely-classified record rather than whichever file glob
    # happened to sort first alphabetically.
    SOURCE_PRIORITY = ["hackerone.jsonl", "ghsa.jsonl", "tryhackme.jsonl", "hackthebox.jsonl", "ctf.jsonl", "community_submissions.jsonl", "blogs.jsonl", "pentesterland.jsonl", "curated_lists.jsonl", "rss_feeds.jsonl"]
    all_files = sorted(glob.glob(os.path.join(args.raw_dir, "*.jsonl")))
    ordered_files = sorted(all_files, key=lambda p: SOURCE_PRIORITY.index(os.path.basename(p)) if os.path.basename(p) in SOURCE_PRIORITY else len(SOURCE_PRIORITY))

    # Read any existing output fully into memory first -- --existing and --out
    # are typically the same path (merge new records into the current dataset
    # in place), so this must happen before args.out is opened for writing.
    existing_lines = []
    if args.existing and os.path.exists(args.existing):
        with open(args.existing) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                existing_lines.append(line)
                rec = json.loads(line)
                seen_ids.add(rec["id"])
                url = rec.get("source", {}).get("url")
                if url:
                    seen_urls.add(url)
        total_existing = len(existing_lines)

    with open(args.out, "w") as out_f:
        for line in existing_lines:
            out_f.write(line + "\n")
            total_out += 1

        for raw_path in ordered_files:
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

                    raw_url = raw.get("url")
                    if raw_url and raw_url in seen_urls:
                        total_cross_platform_dupes += 1
                        continue

                    if platform == "hackerone":
                        text_fields = [raw.get("weakness"), raw.get("title")]
                        tag_field = raw.get("weakness")
                    elif platform == "aggregated_writeup":
                        text_fields = (raw.get("bugs") or []) + [raw.get("title")]
                        tag_field = " ".join(raw.get("bugs") or [])
                    elif platform == "ctf":
                        text_fields = [raw.get("title")]
                        tag_field = raw.get("title")
                    elif platform == "tryhackme":
                        text_fields = [raw.get("title")]
                        tag_field = raw.get("title")
                    elif platform == "hackthebox":
                        text_fields = [raw.get("title")]
                        tag_field = raw.get("title")
                    elif platform == "ghsa":
                        text_fields = tag_field = None  # classified separately below, by real CWE
                    else:
                        continue

                    if platform == "ghsa":
                        # Real, published CWE ID(s) beat any keyword match -- classify
                        # by CWE first, using the title only to disambiguate playbooks
                        # that share a CWE (see classify_by_cwe).
                        playbook_id, confidence = classify_by_cwe(raw.get("cwe_ids"), raw.get("title"), cwe_index, alias_map)
                    else:
                        # Prefer classifying on the dedicated tag field first (higher signal),
                        # fall back to full text fields.
                        playbook_id, confidence = classify([tag_field], alias_map)
                        if not playbook_id:
                            playbook_id, confidence = classify(text_fields, alias_map)
                            if playbook_id:
                                confidence = "low"

                    # Room/box/challenge titles are often thematic (e.g. "Blue", "Ice")
                    # rather than vulnerability-descriptive; fall back to the platform's
                    # generic solving playbook instead of dropping the record.
                    if not playbook_id and platform == "tryhackme":
                        playbook_id, confidence = "tryhackme_room_generic", "low"
                    if not playbook_id and platform == "hackthebox":
                        playbook_id, confidence = "hackthebox_box_generic", "low"
                    if not playbook_id and platform == "ctf":
                        playbook_id, confidence = "ctf_challenge_generic", "low"

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
                    if raw_url:
                        seen_urls.add(raw_url)

                    out_f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    total_out += 1
                    count_this_source += 1

    print(f"Kept {total_existing} existing scenarios, read {total_in} new raw records, wrote {total_out} scenarios total, skipped {total_skipped} (unclassified), {total_cross_platform_dupes} cross-platform/existing URL duplicates dropped", file=sys.stderr)
    print(f"Skip breakdown by source: {skip_reasons}", file=sys.stderr)


if __name__ == "__main__":
    main()
