"""
Intel Pipeline — Spamhaus ASN-DROP Feed Puller
Source: Spamhaus ASN-DROP JSON list (spamhaus.org)
No authentication required. Pull at most once per day — enforced by daily schedule.
Tier 1 — high authority for malicious ASNs (bulletproof hosting, C2 netblocks).
"""

import requests
from src.feeds.base import BaseFeed

SPAMHAUS_ASNDROP_URL = "https://www.spamhaus.org/drop/asndrop.json"


class SpamhausAsnDropFeed(BaseFeed):
    name        = "Spamhaus ASN-DROP"
    tier        = 1
    base_weight = 80.0
    timeout     = 30

    def pull(self):
        response = requests.get(SPAMHAUS_ASNDROP_URL, timeout=self.timeout)
        response.raise_for_status()

        # Response is newline-delimited JSON objects (NDJSON)
        entries = []
        for line in response.text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                import json
                obj = json.loads(line)
                asn = obj.get("asn")
                if asn is None:
                    continue
                entries.append({
                    "type":  "asn",
                    "value": str(asn),
                    "suggested_severity": "high",
                    "evidence_class": "Infrastructure",
                })
            except Exception:
                continue

        return entries
