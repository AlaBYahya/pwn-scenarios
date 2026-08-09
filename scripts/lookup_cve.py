#!/usr/bin/env python3
"""Look up a CVE's CVSS score and summary against NVD, for verifying entries
before adding them to knowledge/graph/technology_bridges.json.

Uses the NVD_API_KEY environment variable if set (50 requests/30s instead of
the unauthenticated 5/30s) -- get a free key at
https://nvd.nist.gov/developers/request-an-api-key. Never hardcode the key;
export it locally or set it as a GitHub Actions secret.

Usage:
    export NVD_API_KEY=...     # optional
    python3 lookup_cve.py CVE-2021-44228
    python3 lookup_cve.py CVE-2021-44228 CVE-2022-22965 CVE-2020-1472
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup(cve_id, api_key):
    headers = {"user-agent": "pwn-scenarios-collector/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(f"{API_URL}?cveId={cve_id}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None

    cve = vulns[0]["cve"]
    descriptions = cve.get("descriptions") or []
    summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

    metrics = cve.get("metrics") or {}
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0]["cvssData"]["baseScore"]
            break

    return {"cve_id": cve_id, "cvss": cvss, "summary": summary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cve_ids", nargs="+", help="One or more CVE IDs, e.g. CVE-2021-44228")
    args = ap.parse_args()

    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        print("NVD_API_KEY not set -- using the unauthenticated rate limit (5 req/30s).", file=sys.stderr)

    delay = 0.6 if api_key else 6.0
    for i, cve_id in enumerate(args.cve_ids):
        if i:
            time.sleep(delay)
        try:
            result = lookup(cve_id, api_key)
        except urllib.error.HTTPError as e:
            print(f"{cve_id}: HTTP {e.code} -- {e.reason}", file=sys.stderr)
            continue
        if result is None:
            print(f"{cve_id}: not found", file=sys.stderr)
            continue
        print(f"{result['cve_id']}  CVSS {result['cvss']}")
        print(f"  {result['summary']}")


if __name__ == "__main__":
    main()
