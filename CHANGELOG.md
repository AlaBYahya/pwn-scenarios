# Changelog

Engineering history: what changed, why, and what was evaluated and rejected.
For what the dataset *is* and how to use it, see [README.md](README.md).

## Round 6 -- blockchain domain, CWE-grounded GHSA source

- **7 new blockchain/smart-contract playbooks**: reentrancy, integer
  overflow/underflow, access control, price oracle manipulation, flash
  loan attacks, unchecked external call/delegatecall injection, and
  front-running/MEV -- grounded in the SWC Registry and DASP Top 10
  classification frameworks (not the unverified "Ultimate Offensive Red
  Team" mega-dataset that was evaluated and rejected: unspecified license
  per an independent trust audit, re-uploaded near-identically under four
  unrelated HF accounts). Added a new `blockchain` target type. Attack
  graph grew 293->329 states, 271->299 actions.
- **New source: GitHub Security Advisories (GHSA)**, reviewed only, 2,514
  records. Unlike every prior source, classification here doesn't rely on
  keyword-matching a headline -- each advisory carries a real, published
  CWE ID, so `normalize.py` maps it directly to a playbook
  (`classify_by_cwe`), falling back to alias matching only to disambiguate
  when several playbooks share a CWE (e.g. CWE-287 covers 4 different auth
  classes). Result: 2,026 high-confidence + 488 medium-confidence records,
  zero low-confidence and zero unclassified out of 2,514 -- the cleanest
  batch of any source so far. Also gave the new blockchain classes their
  first grounded instances (Price Oracle Manipulation: 87, Integer
  Overflow/Underflow: 92, Unchecked External Call: 24, Reentrancy: 8) and
  boosted previously thin classes (JWT 19->100, Mass Assignment 14->69,
  Hardcoded Secrets 13->62, SSTI 38->114).
- Wired `collect_ghsa.py` into `weekly-collect.yml`'s full-rebuild source
  list before running anything for real -- weekly does a from-scratch
  rebuild with no `--existing` (by design, since it fully re-collects
  every source), so omitting GHSA there would have silently deleted every
  GHSA record on the next scheduled run. Same bug class as the
  daily-collect destructive-rebuild incident; caught this time before it
  could fire.
- Ran the full weekly pipeline for real (not just a local merge) to
  validate GHSA end-to-end and refresh every other source at the same
  time: **30,303 -> 31,995 records, 42 -> 47 vulnerability classes,
  high-confidence share 54% -> 58%**. Synced to the HF mirror
  (aeby/pwn-scenarios) automatically as part of the same run.
- **Immunefi checked and mostly rejected for now**: built
  `collect_immunefi.py` against a curated community list of 135 real,
  disclosed smart-contract bug bounty writeups (Wormhole $10M, Aurora $6M,
  Optimism $2M, and more). The table has no vulnerability-class tag, so
  classification fell back to words extracted from the writeup URL slug --
  yielded only 2/135 classified (DeFi postmortem slugs like
  "infinite-money-duplication" or "uninitialized-proxy-bugfix-review"
  don't overlap with our alias vocabulary). Fetching each writeup's actual
  page title for a stronger signal was tried and blocked (Medium sits
  behind a Cloudflare challenge for unauthenticated fetches). Not merged
  into the dataset at that yield -- script kept for later if a better
  signal source turns up.
- **Rekt.news checked and deferred**: real, well-documented DeFi hack
  post-mortems, but no sitemap.xml or rss.xml (Next.js app, both return
  HTTP 500) -- would need direct page-list scraping rather than the feed
  based approach every other blog source uses. Not attempted this round.

## Round 5 -- CVE chain expansion, source diversity, scheduled collection

- **17 CVE chains total** (was 8): added Zerologon, EternalBlue,
  PrintNightmare, Follina, MOVEit Transfer, Citrix Bleed, Cisco IOS XE web
  UI RCE, the Ivanti Connect Secure auth-bypass-to-RCE chain, and a GitLab
  password-reset account takeover. All CVE IDs/CVSS verified against NVD.
  Greedy-policy graph goal-reach rate improved 13.1% -> 18.1% as a direct
  result (several of the new chains grant SYSTEM/domain-admin in a single
  confirmed step).
- **Three new curated-list sources**, each needing a different parser:
  Facebook-BugBounty-Writeups (109 records, bespoke
  `- **[DATE - $BOUNTY]** [Title](url) by [Author](url)` template),
  awesome-google-vrp-writeups (244 records from a plain `writeups.csv`),
  awesome-llm-security (35 records, standard markdown list).
- **Real bug bounty vs. lab/CTF tension**: raising CTF/HackTheBox/TryHackMe
  repo-search limits for more records directly worked against the
  rebalancing done in Round 4. Pushed CTF to 150 repos/topic first (dropped
  real-bug-bounty share 60.2% -> 53.9%), dialed back to 70 repos/topic as a
  middle ground (56.4% final). Trade-off to keep in mind when tuning
  collector limits in either direction.
- **YesWeHack** checked and rejected: `robots.txt` explicitly disallows
  `/reports/` and `/vulnerability-center/` -- respected, not worked around.
- **bugbountydaily.com** checked and rejected: client-rendered
  React/Supabase app, no feed/sitemap/API.
- Added `.github/workflows/daily-collect.yml` (RSS feeds + blogs, since
  those only return ~10-20 recent posts per fetch) and
  `weekly-collect.yml` (full pipeline: HackerOne, curated lists,
  CTF/HackTheBox/TryHackMe repo scans) for ongoing passive growth.

## Round 4 -- bug bounty rebalancing, chunking, Intigriti

- **Real bug bounty share: 55.2% -> 60.2%**, with zero new scraping. 3,080
  of the 12,386 already-collected HackerOne reports were unclassified
  because their `weakness` value (HackerOne's own CWE-based taxonomy --
  "Improper Access Control - Generic", "Cryptographic Issues - Generic")
  didn't match any playbook alias. Added ~50 aliases across 10 playbooks
  plus a new `cryptographic_issues` playbook (CWE-310; 211 records landed
  immediately).
- Added Intigriti's platform blog RSS feed (distinct from their
  disclosed-reports API, which requires auth) to the renamed
  `collect_rss_feeds.py` (was `collect_medium_feeds.py`).
- **insecrez/Bug-bounty-Writeups** (783 links) had been misjudged as
  tools-only and skipped in an earlier pass -- its writeup content uses
  `<a href="url">Title</a>` inside markdown tables, not the `[Title](url)`
  list format the collector originally parsed, so the first pass found zero
  matches. Fixed with a second parser.
- **Chunking**: `scenarios.jsonl` crossed GitHub's 50MB single-file warning
  past ~25k records. Split into ~5MB fixed-size chunks under
  `data/scenarios/chunks/` (`scripts/chunk_scenarios.py`) with a
  `manifest.json` SHA256 checksum, verified by CI on every push.
  `scenarios.jsonl` itself became a gitignored local working file,
  reassembled with `cat chunks/*.jsonl >`.

## Round 3 -- HackTheBox, CTF file-level fix, community contributions, AI/LLM classes

- **CTF and HackTheBox collectors fixed from repo-level to file-level**:
  both originally indexed one record per *repository* (`ctf` was 169
  records total) despite the `ctf-writeups` GitHub topic alone spanning
  1,800+ repos, each often containing dozens of individual challenge
  writeups. Rewrote both to walk each repo's file tree, one record per
  challenge/machine file, cross-repo deduplication by normalized title
  (most-starred repo wins) so the same popular box isn't counted once per
  repo that covers it.
- Two bugs found building this: GitHub's own `.github/ISSUE_TEMPLATE/*.md`
  files were slipping through as fake "writeup titles" (fixed by excluding
  `.github` from the path walk, retroactively applied to TryHackMe too),
  and repos using sequential numbering (`1.md`, `2.md`) produced
  content-free titles like "1" (fixed by dropping purely-numeric titles).
- Added `hackthebox` as a platform (schema + `hackthebox_box_generic`
  playbook, same treatment as `tryhackme_room_generic`).
- **9 new AI/LLM playbooks** covering the OWASP Top 10 for LLM Applications
  (2025), wired into the attack graph via `knowledge/graph/ai_bridges.json`
  -- which adds zero new states, since every AI class converges into
  capability states the web/app classes already use (prompt-injection tool
  abuse reaches the same `unauthorized_privileged_action_possible` IDOR
  reaches). Real-world grounding was thin at this point: only
  `prompt_injection` (22) and `model_denial_of_service` (1) matched
  anything.
- **Contribution mechanism**: `.github/ISSUE_TEMPLATE/submit-writeup.yml`
  issue form + `scripts/ingest_submissions.py` +
  `.github/workflows/validate.yml` CI (schema validation, graph
  regeneration check, chunk/view record-count checks).
- Dataset: 7,342 -> 16,436 records across this round.

## Round 2 -- the attack decision graph

- Introduced `data/graph/attack_graph.json`: states are
  conditions/capabilities, actions branch into qualitatively-scored
  outcomes leading to new states -- built to answer "what should I try
  next" rather than just "how do I find X."
- `knowledge/graph/bridges.json`: hand-authored shared capability states
  (e.g. `low_priv_shell_obtained`, `full_host_compromise`) that let
  multiple vulnerability classes converge and chain, instead of 35
  disconnected trees.
- `knowledge/graph/technology_bridges.json`: first 8 real CVE chains
  (Log4Shell, Spring4Shell, and 6 more), verified against NVD.
- `scripts/simulate_graph.py`: samples synthetic episodes via Bellman value
  iteration (a naive 1-step-lookahead greedy policy turned out
  statistically indistinguishable from random, since most early recon
  states share the same generic "low" value -- value iteration looks past
  that).
- `scripts/query_graph.py`: candidate-move lookahead and best-path search
  CLI.

## Round 1 -- initial dataset

- Established the core design: an originally-authored generic
  preconditions/steps/impact/remediation playbook per vulnerability class,
  paired with real, publicly disclosed instance metadata (never the
  writeup's full text -- see `DATA_LICENSE`).
- Sources: HackerOne Hacktivity API, Pentester Land, GitHub CTF/TryHackMe
  writeup repos.
- 35 initial vulnerability playbooks, ~7,342 records.

## Sources evaluated and rejected (cumulative)

Kept here rather than repeated per-round: platforms/sites checked and not
integrated, with the specific reason.

| Source | Reason |
|---|---|
| Open Bug Bounty | Cloudflare bot-detection challenge; not bypassed |
| Intigriti (reports API) | Requires authenticated account; their blog RSS is used instead |
| Bugcrowd `crowdstream` | Live submission-acceptance feed, not a disclosure archive |
| Weekly Infosec Writeups | Weekly digest bundling other sites' links, not individual writeups; inactive since Nov 2024 |
| bugbountyhunting.com | Sitemap is search-query pages only, not a primary source |
| bugbountyhunter.com/disclosed | Near-total overlap with HackerOne reports already collected directly |
| writeups.io | Client-rendered Next.js app, no public API |
| bugbountydaily.com | Client-rendered React/Supabase app, no feed/sitemap/API |
| YesWeHack | `robots.txt` explicitly disallows `/reports/` and `/vulnerability-center/` |
