# Intel Pipeline

A standalone threat intelligence ingestion, normalization, analyst approval, and export
pipeline. Part of the Night's Watch Home SOC Suite.

Pulls indicators from 8 automated feeds, scores them with corroboration-based confidence,
routes them through an analyst approval queue, and exports approved indicators as signed
JSON snapshots. CVE entries are enriched with NVD version range data and compared against
installed software — export severity reflects whether the endpoint is actually affected.

![Intel Pipeline dashboard — full view](Documentation/Screenshots/intel_full.png)

*Single-page Flask dashboard on port 6001. Feed status strip, manual pull controls,
export management, and a filterable approval queue.*

---

## Features

- **8 automated feed pullers** — Tier 1 and Tier 2 sources covering IPs, domains, URLs,
  hashes, CVEs, and TTPs
- **GreyNoise enrichment** — on-demand IP context during analyst review
- **Installed software scanner** — reads Windows registry at startup, writes a software
  inventory used for CVE relevance gating
- **NVD enrichment** — targeted NVD API v2.0 queries for CVEs where vendor and product
  match installed software; stores version range data per CVE
- **CVE severity gate** — export-time version check downgrades CVE severity to `medium`
  when the installed version falls outside all vulnerable ranges; fails open on missing
  data; re-evaluated on every export so severity stays current as enrichment data improves
- **Corroboration confidence model** — confidence rises when independent sources agree;
  same-source repeat pulls never inflate scores
- **Phase-based confidence decay** — indicators decay in two phases based on type TTL;
  TTPs never expire
- **Analyst-in-the-loop approval** — all indicators must be reviewed and approved before
  export
- **TLP-aware export** — schema 1.1 JSON snapshots with SHA256 sidecar; last 5 snapshots
  retained with rollback support
- **Flask dashboard** — dark-theme single-page app on port 6001; feed health strip,
  approval queue with type filtering, export management

---

## Analyst Workflow

### Approval Queue

Every indicator pulled from a feed lands in the approval queue with a `pending` status.
Analysts filter by type (IP, Domain, Hash, CVE, ASN, TTP, URL) and review each entry
before it becomes eligible for export.

### Review Panel

![Analyst review modal for a pending CVE](Documentation/Screenshots/review_pannel.png)

The review panel shows the full normalized entry — value, confidence score, evidence
class, description, affected vendor and product, source feed, lane (automated / manual),
and expiry. Analysts can add notes, adjust suggested severity and TLP, and choose
**Approve**, **Reject**, or **Alert** (flag for immediate attention).

### Search and Filter

![Search filter showing approved GitHub URL indicators](Documentation/Screenshots/search_function.png)

Free-text search across value and source fields, combined with type and status filters,
enables quick review of specific indicator patterns — here showing approved URL
indicators hosted on GitHub infrastructure from URLhaus feed pulls.

---

## CVE Severity Gate

CVE indicators go through a version-aware severity check at export time. The gate uses
two data sources built during startup and enrichment:

1. **Installed software** (`scanner.py`) — Windows registry scan producing a JSON
   inventory of installed software with name, publisher, and version
2. **NVD version ranges** (`feeds/nvd.py`) — targeted NVD API v2.0 queries for CVEs
   where the CISA KEV vendor and product match an installed package

At export time, `compute_effective_severity()` in `normalizer.py`:

- Applies type ceilings: ASN → max `medium`, TTP → max `low`
- For CVE entries: compares the installed version against NVD vulnerable ranges
  - Version is in a vulnerable range → keep severity
  - Version is outside all ranges → downgrade to `medium`
  - No enrichment data yet, or product not found → fail open (keep severity)
  - Microsoft/Windows → always keep severity (every Windows endpoint is affected)

The gate only downgrades — it never raises severity. If an analyst deliberately set a
lower severity, the gate will not override it upward.

Because the gate fires on every export against current enrichment data, severity in the
export automatically reflects patching: once a package is updated past a vulnerable range,
the next export downgrades that CVE without any manual intervention.

---

## Export and Verification

![Export snapshots modal with rollback option](Documentation/Screenshots/export_snapshot.png)

Exports produce a timestamped schema 1.1 JSON snapshot with a matching SHA256 sidecar.
The last five snapshots are retained, and any previous snapshot can be rolled back as the
current export. Each snapshot records entry count, TLP classification, and the full hash
for verification.

### Export Schema 1.1 Fields

Each indicator in the export includes:

| Field | Description |
|---|---|
| `type` | Indicator type (ip, domain, hash, cve, asn, ttp, url) |
| `value` | Normalized indicator value |
| `evidence_class` | Infrastructure / Artifact / Vulnerability / Behavior |
| `confidence` | Aggregated trust score (0–100) |
| `severity` | Gate-computed effective severity |
| `tlp` | TLP classification |
| `engine_action` | Block / Alert / Log |
| `source_list` | All feeds that reported this indicator |
| `source_count` | Number of independent sources |
| `first_seen` / `last_seen` | Timestamps |
| `expires_at` | Calculated expiry |
| `lane` | automated or human |
| `approved_at` / `approved_by` | Approval metadata |
| `description` | Feed-supplied description or technique name |
| `affected_vendor` | CVE: vendor from CISA KEV |
| `affected_product` | CVE: product from CISA KEV |

Verify the most recent export:

```
python verify_export.py
```

List all retained snapshots:

```
python verify_export.py --list
```

Verify a specific snapshot:

```
python verify_export.py intel_export_20260428_185654_287293_standard.json
```

Exit code 0 = verified. Exit code 1 = tampered or missing.

---

## Feed Sources

| Feed | Type | Tier | Indicators |
|---|---|---|---|
| MITRE ATT\&CK | TTP | 1 | Techniques (T-codes) |
| CISA KEV | CVE | 1 | Known Exploited Vulnerabilities |
| Spamhaus ASN-DROP | ASN | 1 | Hijacked / malicious ASNs |
| MalwareBazaar | Hash | 1 | Recent malware sample SHA256s |
| Feodo Tracker | IP | 1 | Active C2 botnet IPs |
| URLhaus | URL | 2 | Active malware distribution URLs |
| ThreatFox | IP/Domain/URL/Hash | 2 | Multi-type threat indicators |
| AlienVault OTX | IP/Domain/URL/Hash | 2 | Community threat pulses |

GreyNoise is used for IP enrichment only — not a bulk feed source.
NVD is used for CVE version enrichment only — not a bulk feed source.

---

## Confidence Model

- **Base weight** — set per feed (70–85 depending on tier)
- **New independent source** — +10 corroboration bonus
- **Same-source repeat pull** — `last_seen` updated, no bonus
- **Tier 3 sources** — capped at 60 until a Tier 1 source corroborates
- **Expired re-observation** — confidence resets to feed base weight, entry returns to pending

---

## Decay Schedule

| Type | Early phase TTL | Early penalty | Late phase TTL | Late penalty |
|---|---|---|---|---|
| IP / Domain / URL | 7 days | -10 | 21 days | -20 |
| ASN / Hash | 30 days | -10 | 90 days | -20 |
| CVE | 90 days | -10 | 180 days | -20 |
| TTP | permanent | — | — | — |

---

## Setup

### Requirements

- Python 3.10+
- Windows (scanner.py uses `winreg`)
- pip packages: `flask`, `requests`, `python-dotenv`, `packaging`

```
pip install flask requests python-dotenv packaging
```

### API Keys

Copy `config.example.env` to `.env` and fill in your keys:

```
cp config.example.env .env
```

| Key | Source | Required |
|---|---|---|
| `ABUSE_CH_API_KEY` | auth.abuse.ch | Yes (MalwareBazaar, URLhaus, ThreatFox, Feodo) |
| `OTX_API_KEY` | otx.alienvault.com | Yes (OTX) |
| `GREYNOISE_API_KEY` | greynoise.io | No (leave blank for unauthenticated, 10 lookups/day) |
| `NVD_API_KEY` | nvd.nist.gov/developers/request-an-api-key | No (recommended — 50 req/30s vs 5 req/30s) |

MITRE ATT&CK, CISA KEV, and Spamhaus require no API key.

### First Run

```
launch.bat
```

Opens a persistent terminal window and starts the Flask server on port 6001.
Navigate to `http://localhost:6001` in your browser.

The database is created automatically at `Data\intel.db` on first startup.
The installed software inventory is written to `%USERPROFILE%\Desktop\SOC\Config\installed_software.json`
on every startup.

---

## Project Structure

```
Intel\
├── src\
│   ├── app\
│   │   └── app.py              — Flask dashboard (all routes)
│   ├── db\
│   │   ├── database.py         — Schema, migrations, connection, audit log
│   │   └── ingest.py           — Insert / update / corroboration logic
│   ├── feeds\
│   │   ├── base.py             — BaseFeed (pull, normalize, ingest, health log)
│   │   ├── runner.py           — Parallel feed orchestration
│   │   ├── greynoise.py        — IP enrichment (on-demand, not a feed)
│   │   ├── nvd.py              — CVE version enrichment (on-demand, not a feed)
│   │   └── [mitre, cisa_kev, spamhaus, malwarebazaar,
│   │        urlhaus, threatfox, feodo, otx].py
│   ├── normalizer.py           — Raw to normalized entry; type ceilings; CVE severity gate
│   ├── scanner.py              — Windows registry scan → installed_software.json
│   ├── decay.py                — Phase-based confidence decay
│   └── exporter.py             — Schema 1.1 JSON export, SHA256 sidecar, rollback, pruning
├── verify_export.py            — Standalone export verification tool
├── launch.bat                  — Start server (persistent terminal)
├── config.example.env          — API key template (commit this, not .env)
├── .gitignore
└── Documentation\
    ├── Intel_Test_Guide.md
    └── Screenshots\            — Dashboard screenshots used in this README
```

---

## Status Lifecycle

```
pending -> approved / rejected
pending -> pending_review (feed update changes a significant field)
approved -> pending_review (feed update changes a significant field)
approved -> expired (decay reaches 0)
expired -> pending (re-observed by a feed — confidence resets)
```

---

## Part of the Night's Watch Home SOC Suite

This pipeline is the standalone intel layer (Phase 1 + Phase 2A complete).
Phase 2B will integrate the export with the SOC correlation engine via the
SOC dashboard "Update Intel" flow defined in the pipeline design document.
