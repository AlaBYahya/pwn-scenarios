#!/usr/bin/env python3
"""Validate every record in the scenarios dataset against the JSON schema, and
check for duplicate ids/urls.

Usage:
    python3 validate.py --data ../data/scenarios/scenarios.jsonl --schema ../schema/scenario.schema.json
"""
import argparse
import json
import sys

import jsonschema


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/scenarios/scenarios.jsonl")
    ap.add_argument("--schema", default="../schema/scenario.schema.json")
    args = ap.parse_args()

    with open(args.schema) as f:
        schema = json.load(f)
    validator = jsonschema.Draft7Validator(schema)

    ids, urls = set(), set()
    errors = 0
    total = 0

    with open(args.data) as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            total += 1
            record = json.loads(line)

            for err in validator.iter_errors(record):
                errors += 1
                print(f"line {lineno}: schema error: {err.message} (path: {list(err.path)})", file=sys.stderr)

            rid = record.get("id")
            if rid in ids:
                errors += 1
                print(f"line {lineno}: duplicate id {rid}", file=sys.stderr)
            ids.add(rid)

            url = record.get("source", {}).get("url")
            if url in urls:
                errors += 1
                print(f"line {lineno}: duplicate source url {url}", file=sys.stderr)
            urls.add(url)

    print(f"Validated {total} records: {errors} error(s)", file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
