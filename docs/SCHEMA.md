# Scenario schema

Every record in `data/scenarios/scenarios.jsonl` is one JSON object per line,
validated against [`schema/scenario.schema.json`](../schema/scenario.schema.json).
A record is a **generalized, reusable exploitation process** (the "scenario":
preconditions, numbered steps, impact, remediation) **grounded in one real,
publicly disclosed instance** (the "source": a HackerOne report, an aggregated
writeup link, or a CTF writeup repository).

```jsonc
{
  "id": "66d73fac93eda4b6",            // sha256(platform|url)[:16], stable
  "schema_version": "1.0.0",
  "title": "...",                       // title of the real instance

  "vulnerability": {
    "class": "Insecure Direct Object Reference (IDOR)",
    "cwe": "CWE-639",                   // or null
    "owasp_category": "A01:2021 Broken Access Control", // or null
    "severity": "unknown"               // unknown | low | medium | high | critical
  },

  "target": {
    "type": "web",                      // web | api | mobile | cloud | network | binary | iot | other
    "technology_hints": []
  },

  "scenario": {
    "summary": "...",
    "preconditions": ["..."],            // what must be true for this scenario to apply
    "process": [                         // ordered, reusable steps -- the core "playbook"
      {
        "step": 1,
        "action": "...",
        "technique": "...",
        "tools": ["Burp Suite", "..."],
        "expected_observation": "..."   // what you should see if the step succeeds
      }
    ],
    "decision_points": [],
    "impact": ["..."],
    "remediation": ["..."]
  },

  "provenance": {
    "playbook_id": "idor",              // knowledge/vulnerability_playbooks.json entry used
    "grounded_instance": true,
    "confidence": "high"                // high | medium | low -- classification confidence
  },

  "source": {
    "platform": "hackerone",            // hackerone | aggregated_writeup | ctf | tryhackme | other
    "url": "https://hackerone.com/reports/...",
    "program": "...",
    "author": null,
    "disclosed_at": "2026-01-01",
    "bounty": null
  },

  "tags": ["..."],
  "collection_metadata": {
    "collected_at": "2026-08-09T00:00:00Z",
    "collector": "hackerone.jsonl"
  },
  "license_note": "..."
}
```

## Why "process" content is generic, not copied

`scenario.process` (and `preconditions`/`impact`/`remediation`) come from
[`knowledge/vulnerability_playbooks.json`](../knowledge/vulnerability_playbooks.json) --
one authored playbook per vulnerability class, not text extracted from any
specific writeup. Each real-world record is an *instance* of a playbook:
the `source` block carries the concrete, factual metadata (who found what,
where, when), while `scenario` carries the reusable "how this class of bug is
generally found and fixed."

This keeps the dataset genuinely useful as training/RAG material (a
consistent, step-structured process per vulnerability class) while staying on
solid legal ground -- see [`DATA_LICENSE`](../DATA_LICENSE).

## Confidence levels

`provenance.confidence` reflects how the normalizer matched the source
record's tags to a playbook:

- **high** -- an unambiguous, specific tag/weakness match (e.g. HackerOne's
  own `weakness.name`, or a single unambiguous bug-type tag)
- **medium** -- matched among multiple plausible tags on the same record
- **low** -- fell back to matching against the free-text title because no
  dedicated tag matched

Consumers that need higher-precision data can filter to `confidence: "high"`.
