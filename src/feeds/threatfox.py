"""
Intel Pipeline — ThreatFox Feed Puller (Abuse.ch)
Source: ThreatFox API — recent IOCs (IPs, domains, URLs, hashes)
Requires: ABUSE_CH_API_KEY in .env
Pulls IOCs from the last 1 day.
"""

import os
import requests
from dotenv import load_dotenv
from src.feeds.base import BaseFeed

load_dotenv()

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox ioc_type to our indicator types
THREATFOX_TYPE_MAP = {
    "ip:port":  "ip",
    "domain":   "domain",
    "url":      "url",
    "md5_hash": "hash",
    "sha256_hash": "hash",
}


class ThreatFoxFeed(BaseFeed):
    name        = "ThreatFox"
    tier        = 2
    base_weight = 70.0
    timeout     = 30

    def pull(self):
        api_key = os.getenv("ABUSE_CH_API_KEY", "")
        if not api_key:
            raise ValueError("ABUSE_CH_API_KEY not set in .env")

        response = requests.post(
            THREATFOX_URL,
            json={"query": "get_iocs", "days": 1},
            headers={"Auth-Key": api_key},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok":
            raise ValueError(f"ThreatFox API error: {data.get('query_status')}")

        entries = []
        for ioc in data.get("data", []):
            raw_type = ioc.get("ioc_type", "").lower()
            mapped_type = THREATFOX_TYPE_MAP.get(raw_type)
            if not mapped_type:
                continue

            value = ioc.get("ioc", "").strip()
            if not value:
                continue

            # Strip port from ip:port format
            if raw_type == "ip:port" and ":" in value:
                value = value.split(":")[0]

            malware = ioc.get("malware_printable", "").strip()
            threat  = ioc.get("threat_type_desc", "").strip()
            description = malware or threat or None
            if malware and threat:
                description = f"{malware} — {threat}"

            entries.append({
                "type":  mapped_type,
                "value": value,
                "suggested_severity": "high",
                "evidence_class": "Infrastructure" if mapped_type == "ip" else "Artifact",
                "description": description,
            })

        return entries
