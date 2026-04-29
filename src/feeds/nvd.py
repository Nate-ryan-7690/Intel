"""
NVD Enrichment Feed
Fetches CVE version range data from NVD API v2.0 for entries that match
installed software. Only queries CVEs where affected_vendor + affected_product
match installed_software.json. Writes version ranges to nvd_versions column.

NULL nvd_versions  = not yet fetched
[]   nvd_versions  = fetched, no version data found (or hardcoded match)
[..] nvd_versions  = fetched, version ranges stored

Requires: NVD_API_KEY in .env (optional but recommended — 50 req/30s vs 5 req/30s)
Register at: https://nvd.nist.gov/developers/request-an-api-key
"""

import json
import os
import time
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

from src.db.database import get_connection, write_audit

# --- Config ---
NVD_API_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
INSTALLED_SW_PATH = os.path.join(
    os.environ["USERPROFILE"], "Desktop", "SOC", "Config", "installed_software.json"
)

# Rate limits: requests per RATE_WINDOW seconds
RATE_LIMIT_WITH_KEY    = 50
RATE_LIMIT_WITHOUT_KEY = 5
RATE_WINDOW            = 30  # seconds


def _load_installed_software():
    try:
        with open(INSTALLED_SW_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("software", [])
    except Exception as e:
        print(f"[NVD] Could not load installed software: {e}")
        return []


def _matches_installed(vendor, product, software_list):
    """
    Strict dual-check: vendor must appear in publisher AND product in name.
    Microsoft + Windows is hardcoded as always present — skip API call.
    Returns (matches: bool, hardcoded: bool).
    """
    vendor_l  = vendor.lower().strip()
    product_l = product.lower().strip()

    if not vendor_l or not product_l:
        return False, False

    # Microsoft + Windows: every Windows endpoint qualifies — no version check needed
    if vendor_l == "microsoft" and product_l.startswith("windows"):
        return True, True

    for sw in software_list:
        name_l = (sw.get("name")      or "").lower()
        pub_l  = (sw.get("publisher") or "").lower()
        if vendor_l in pub_l and product_l in name_l:
            return True, False

    return False, False


def _fetch_nvd(cve_id, api_key=None):
    """
    Fetch NVD API for a single CVE.
    Returns list of version match dicts, [] if no data, None if fetch failed.
    """
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[NVD] Fetch failed for {cve_id}: {e}")
        return None  # None = failed, do not mark as fetched

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return []  # CVE known to NVD but no configuration data

    versions = []
    for config in vulns[0].get("cve", {}).get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                versions.append({
                    "criteria":              match.get("criteria", ""),
                    "versionStartIncluding": match.get("versionStartIncluding"),
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding":   match.get("versionEndIncluding"),
                    "versionEndExcluding":   match.get("versionEndExcluding"),
                })
    return versions


def run_nvd_enrichment():
    """
    Enrich CVE entries matching installed software with NVD version ranges.
    Skips entries where nvd_versions is already populated.
    Microsoft/Windows entries are marked immediately without an API call.
    """
    api_key  = os.getenv("NVD_API_KEY", "").strip() or None
    rate_cap = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_WITHOUT_KEY
    delay    = RATE_WINDOW / rate_cap

    software = _load_installed_software()
    if not software:
        return {"enriched": 0, "hardcoded": 0, "skipped": 0, "failed": 0,
                "error": "installed_software.json not found"}

    conn = get_connection()
    rows = conn.execute("""
        SELECT id, value, affected_vendor, affected_product
        FROM intel_entries
        WHERE type             = 'cve'
          AND affected_vendor  IS NOT NULL AND affected_vendor  != ''
          AND affected_product IS NOT NULL AND affected_product != ''
          AND nvd_versions     IS NULL
          AND status           != 'rejected'
    """).fetchall()
    conn.close()

    enriched  = 0
    hardcoded = 0
    skipped   = 0
    failed    = 0
    start     = datetime.now(timezone.utc)

    for row in rows:
        matches, is_hardcoded = _matches_installed(
            row["affected_vendor"], row["affected_product"], software
        )

        if not matches:
            skipped += 1
            continue

        # Microsoft/Windows — always HIGH, mark immediately without API call
        if is_hardcoded:
            conn = get_connection()
            conn.execute(
                "UPDATE intel_entries SET nvd_versions = ? WHERE id = ?",
                (json.dumps([]), row["id"])
            )
            conn.commit()
            conn.close()
            hardcoded += 1
            continue

        versions = _fetch_nvd(row["value"], api_key)
        time.sleep(delay)

        if versions is None:
            failed += 1
            continue

        conn = get_connection()
        conn.execute(
            "UPDATE intel_entries SET nvd_versions = ? WHERE id = ?",
            (json.dumps(versions), row["id"])
        )
        conn.commit()
        conn.close()
        enriched += 1

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    summary = (f"Enriched: {enriched} | Hardcoded: {hardcoded} | "
               f"Skipped: {skipped} | Failed: {failed} | {elapsed:.1f}s")
    print(f"[NVD] {summary}")
    write_audit("NVD_ENRICHMENT", detail=summary)

    return {"enriched": enriched, "hardcoded": hardcoded,
            "skipped": skipped, "failed": failed}
