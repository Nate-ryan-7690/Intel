# Intel Pipeline — Test Guide
All tests logged in order of execution. Append after every test run — never delete entries.

---

## Test 001 — Database Initialisation
**Date:** 2026-04-10
**File:** `src/db/database.py`
**Command:** `py src/db/database.py`
**What it tests:** Database creation, all 6 tables, feed config seed for all 9 feeds.
**Result:** PASS
**Output:**
```
[2026-04-10 09:38:47] Database initialised at ...\Intel\Data\intel.db
[2026-04-10 09:38:47] Feed configuration seeded.
```
**Notes:** Initial run produced a deprecation warning on `datetime.utcnow()` — fixed immediately, replaced with `datetime.now(timezone.utc)` across the module. Clean on second run.

---

## Test 002 — Normalizer Output
**Date:** 2026-04-10
**File:** `src/normalizer.py`
**Command:** `py -c "from src.normalizer import ..."`
**What it tests:** Automated entry normalisation, deduplication key resolution, human entry normalisation.
**Result:** PASS
**Checks:**
- Automated IP entry from ThreatFox (Tier 2): TLP:GREEN, severity high, 45-day TTL, lane automated — correct
- Dedup key: `www.evil.com` and `evil.com` both resolve to `('domain', 'evil.com')` — correct
- CVE normalisation: `cve-2026-1234` → `CVE-2026-1234` — correct
- ASN normalisation: `13335` → `AS13335` — correct
- Human entry: TLP:AMBER for Tier 3, lane human, confidence 60 — correct
**Notes:** No issues.

---

## Test 003 — Ingest Layer
**Date:** 2026-04-10
**File:** `src/db/ingest.py`
**Command:** `py -c "from src.db.ingest import ingest_entry, ingest_batch ..."`
**What it tests:** New entry insertion, independent source corroboration, repeat sighting bonus, batch ingest.
**Result:** PASS
**Checks:**
- New IP entry from ThreatFox inserted with status pending — correct
- Same IP from Feodo Tracker (independent source): +10 corroboration bonus — correct
- Same IP from ThreatFox again (repeat sighting): +3 bonus — correct
- Final confidence: 83.0 (70 + 10 + 3 = 83) — correct
- Source list: ["ThreatFox", "Feodo Tracker"], source_count: 2 — correct
- Batch ingest of 3 entries: 3 inserted, 0 errors — correct
**Notes:** No issues.

---

## Test 004 — Feed Runner Import & Feed Map
**Date:** 2026-04-10
**File:** `src/feeds/runner.py`
**Command:** `py -c "from src.feeds.runner import FEED_MAP ..."`
**What it tests:** All 8 feed pullers import correctly, runner feed map populated.
**Result:** PASS
**Checks:**
- All 8 feeds registered in FEED_MAP: AlienVault OTX, CISA KEV, Feodo Tracker, MITRE ATT&CK, MalwareBazaar, Spamhaus ASN-DROP, ThreatFox, URLhaus — correct
**Notes:** No issues.

---

## Test 005 — CISA KEV End-to-End Pull
**Date:** 2026-04-10
**File:** `src/feeds/cisa_kev.py`, `src/feeds/base.py`, `src/db/ingest.py`
**Command:** `py -c "from src.feeds.runner import run_single_feed; run_single_feed('CISA KEV')"`
**What it tests:** Full pipeline for a no-auth feed — pull → normalise → ingest → feed health log.
**Result:** PASS
**Checks:**
- Status: success — correct
- Raw count: 1559 CVEs pulled from CISA KEV — correct
- Inserted: 1559, errors: 0 — correct
- Feed health logged to database — correct
**Notes:** No issues. Full pipeline confirmed working end-to-end on a no-auth Tier 1 feed.

---

## Test 006 — MalwareBazaar Authenticated Pull
**Date:** 2026-04-10
**File:** `src/feeds/malwarebazaar.py`
**Command:** `py -c "run_single_feed('MalwareBazaar')"`
**What it tests:** abuse.ch API key authentication, hash ingest.
**Result:** PASS
**Checks:** Status success, 100 hashes inserted, 0 errors — correct
**Notes:** No issues.

---

## Test 007 — ThreatFox, URLhaus, Feodo Tracker Authenticated Pulls
**Date:** 2026-04-10
**Files:** `src/feeds/threatfox.py`, `src/feeds/urlhaus.py`, `src/feeds/feodo.py`
**What it tests:** abuse.ch auth across remaining three feeds.
**Result:** PASS (after URLhaus fix)
**Checks:**
- ThreatFox: 482 raw, 480 inserted — correct (2 skipped due to unsupported type)
- Feodo Tracker: 5 C2 IPs inserted — correct
- URLhaus: FAILED initially — 405 Method Not Allowed. Root cause: puller used POST, API requires GET. Fixed in `urlhaus.py`. Retest: 398 raw, 397 inserted — correct
**Notes:** URLhaus endpoint `https://urlhaus-api.abuse.ch/v1/urls/recent/` requires GET not POST. Fixed.

---

## Test 008 — Spamhaus ASN-DROP and AlienVault OTX Pulls
**Date:** 2026-04-10
**Files:** `src/feeds/spamhaus.py`, `src/feeds/otx.py`
**What it tests:** No-auth Spamhaus NDJSON parse, OTX API key auth and pagination.
**Result:** PASS
**Checks:**
- Spamhaus: 398 ASNs inserted — correct
- OTX: 62 raw, 58 inserted (4 skipped — unsupported indicator types) — correct
**Notes:** No issues.

---

## Test 009 — MITRE ATT&CK Pull
**Date:** 2026-04-10
**File:** `src/feeds/mitre.py`
**What it tests:** Large STIX JSON download, technique extraction, TTP ingest.
**Result:** PASS
**Checks:** 691 techniques/sub-techniques inserted, 0 errors — correct
**Notes:** Large file — 60s timeout applied. No issues.

---

## Test 010 — Decay Calculation (Phase-Based)
**Date:** 2026-04-10
**File:** `src/decay.py`
**Command:** `py -c "from src.decay import _calculate_decay ..."`
**What it tests:** Phase-based flat decay for all indicator types, TTL expiry, TTP permanence.
**Result:** PASS (after logic fix)
**Checks:**
- IP grace (3d): 70 → 70, not expired — correct
- IP early phase (10d): 70 → 60 (-10 flat), not expired — correct
- IP late phase (25d): 70 → 40 (-10 -20 flat), not expired — correct
- IP TTL (45d): expired — correct
- ASN grace (20d): 80 → 80 — correct
- ASN early (60d): 80 → 70 — correct
- ASN late (100d): 80 → 50 — correct
- ASN TTL (180d): expired — correct
- CVE grace (50d): 85 → 85 — correct
- CVE early (120d): 85 → 75 — correct
- CVE late (200d): 85 → 55 — correct
- CVE TTL (365d): expired — correct
- TTP (500d): 85 → 85, not expired — correct
**Notes:** Initial implementation applied penalties per-day — incorrect. Fixed to flat per-phase penalties as specified in document Section 7.4.

---

## Test 011 — Decay Engine Live Run
**Date:** 2026-04-10
**File:** `src/decay.py`
**Command:** `py -c "from src.decay import run_decay; run_decay()"`
**What it tests:** Decay engine processes all live database entries without errors.
**Result:** PASS
**Checks:** 3,692 entries checked, 0 decayed, 0 expired — correct (all entries ingested today, all within grace period)
**Notes:** No issues. Decay will apply once entries age past their grace windows.

---

## Test 012 — Export Module
**Date:** 2026-04-10
**File:** `src/exporter.py`
**Command:** `py -c "from src.exporter import generate_export, verify_export ..."`
**What it tests:** Export generation, SHA256 sidecar, hash verification, urgent export, snapshot pruning, rollback.
**Result:** PASS (after two fixes)
**Checks:**
- Standard export: 5 approved indicators, TLP:GREEN, JSON + SHA256 sidecar written — correct
- Hash verification: valid — correct
- Urgent export: export_type reflected in filename — correct
- Snapshot pruning: 6 exports generated, 5 retained — correct
- Rollback: restored from oldest snapshot, registered as new 'rollback' export, 5 snapshots retained — correct
**Fixes applied:**
- Filename collision when exports generated within same second — added microseconds (`%f`) to filename format
- UnicodeEncodeError on Windows console for arrow character in rollback print — replaced with ASCII equivalent
**Notes:** No issues after fixes.

---

## Test 013 — Verification Script
**Date:** 2026-04-10
**File:** `verify_export.py`
**Commands:** `py verify_export.py --list`, `py verify_export.py`, `py verify_export.py <filename>`
**What it tests:** All three script modes — list snapshots, verify most recent, verify specific file.
**Result:** PASS
**Checks:**
- List mode: all 5 retained snapshots shown with ID, date, type, entries, TLP, filename — correct
- Default mode: most recent export verified, hashes match — correct
- Specific filename mode: named export verified, hashes match — correct
- Exit code 0 on pass confirmed
**Notes:** No issues.

---

## Test 014 — Flask App Import and Route Registration
**Date:** 2026-04-10
**File:** `src/app/app.py`
**Command:** `py -c "from src.app.app import app; ..."`
**What it tests:** Flask app imports cleanly, all 15 routes registered.
**Result:** PASS
**Checks:** All routes present — /, /approve, /entry, /export, /export/urgent, /feed_health, /manual, /note, /pull/all, /pull/<feed>, /queue, /reject, /rollback, /search, /snapshots — correct
**Notes:** No issues.

---

## Test 015 — Flask App Startup and HTTP Response
**Date:** 2026-04-10
**File:** `src/app/app.py`
**Command:** `py src/app/app.py` + `curl http://127.0.0.1:6001/`
**What it tests:** App starts on port 6001, DB initialises on startup, decay runs on startup, HTTP 200 returned.
**Result:** PASS
**Checks:** HTTP 200 on /, port 6001 confirmed, DB init and decay logged on startup — correct
**Notes:** No issues.

---

## Test 016 — Description Field in Modal and Queue Table
**Date:** 2026-04-10
**File:** `src/app/app.py`, feed pullers
**What it tests:** Description field stored per feed, displayed in modal and queue table.
**Result:** PASS
**Checks:**
- MITRE ATT&CK technique name shown in modal (e.g. T1114.002 — Remote Email Collection) — correct
- Description column visible in queue table — correct
- Feeds without descriptions show dash placeholder — correct
**Notes:** Feeds repulled to backfill descriptions. All 689 TTPs and 1,554 CVEs updated. Port changed from 6000 to 6001 — Chrome and Edge block port 6000 (ERR_UNSAFE_PORT).

---

## Test 017 — Queue Type Filter and Pagination
**Date:** 2026-04-10
**File:** `src/app/app.py`
**What it tests:** Type filter buttons narrow queue by indicator type, pagination 50 per page.
**Result:** PASS
**Checks:** Filter buttons work, pagination controls appear, page state preserved — correct
**Notes:** No issues.

---

## Test 018 — Full Approval Workflow End-to-End
**Date:** 2026-04-10
**File:** `src/app/app.py`
**What it tests:** Approve, reject, manual entry, corroboration, rejection note enforcement.
**Result:** PASS
**Checks:**
- Approve: row removed from queue — correct
- Reject without note: blocked with error — correct
- Manual entry (GitHub reference for T1027): ingested as pending — correct
- Corroboration: confidence updated on existing entry — correct
**Notes:** No issues.

---
