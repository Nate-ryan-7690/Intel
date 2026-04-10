"""
Intel Pipeline — AlienVault OTX Feed Puller
Source: OTX subscribed pulses — mixed IOC types
Requires: OTX_API_KEY in .env
Pulls indicators from pulses modified in the last 1 day.
Free tier: 10,000 requests/hour — no practical limit for daily pulls.
"""

import os
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from src.feeds.base import BaseFeed

load_dotenv()

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Map OTX indicator types to our types
OTX_TYPE_MAP = {
    "IPv4":         "ip",
    "IPv6":         "ip",
    "domain":       "domain",
    "hostname":     "domain",
    "URL":          "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
    "CVE":          "cve",
}


class OTXFeed(BaseFeed):
    name        = "AlienVault OTX"
    tier        = 3
    base_weight = 55.0
    timeout     = 30

    def pull(self):
        api_key = os.getenv("OTX_API_KEY", "")
        if not api_key:
            raise ValueError("OTX_API_KEY not set in .env")

        # Pull pulses modified in the last day
        since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )

        entries = []
        url = OTX_URL
        params = {"modified_since": since, "limit": 50}

        while url:
            response = requests.get(
                url,
                headers={"X-OTX-API-KEY": api_key},
                params=params,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            for pulse in data.get("results", []):
                for indicator in pulse.get("indicators", []):
                    raw_type = indicator.get("type", "")
                    mapped_type = OTX_TYPE_MAP.get(raw_type)
                    if not mapped_type:
                        continue

                    value = indicator.get("indicator", "").strip()
                    if not value:
                        continue

                    entries.append({
                        "type":  mapped_type,
                        "value": value,
                        "suggested_severity": "low",
                        "evidence_class": "Infrastructure" if mapped_type == "ip" else "Artifact",
                    })

            # Paginate
            next_url = data.get("next")
            if next_url:
                url = next_url
                params = {}
            else:
                break

        return entries
