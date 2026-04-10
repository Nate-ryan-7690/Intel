"""
Intel Pipeline — CISA Known Exploited Vulnerabilities Feed Puller
Source: CISA KEV JSON catalog
No authentication required. High authority — Tier 1.
"""

import requests
from src.feeds.base import BaseFeed

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CisaKevFeed(BaseFeed):
    name        = "CISA KEV"
    tier        = 1
    base_weight = 85.0
    timeout     = 30

    def pull(self):
        response = requests.get(CISA_KEV_URL, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()

        entries = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "").strip()
            if not cve_id:
                continue

            name        = vuln.get("vulnerabilityName", "").strip()
            required    = vuln.get("requiredAction", "").strip()
            description = name
            if required:
                description = f"{name} — Required action: {required}"

            entries.append({
                "type":  "cve",
                "value": cve_id,
                "suggested_severity": "high",
                "evidence_class": "Vulnerability",
                "description": description,
            })

        return entries
