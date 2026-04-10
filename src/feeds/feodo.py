"""
Intel Pipeline — Feodo Tracker Feed Puller (Abuse.ch)
Source: Feodo Tracker — C2 botnet IP blocklist
Requires: ABUSE_CH_API_KEY in .env (required as of June 30, 2025)
Pulls active C2 botnet IPs.
"""

import os
import requests
from dotenv import load_dotenv
from src.feeds.base import BaseFeed

load_dotenv()

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoTrackerFeed(BaseFeed):
    name        = "Feodo Tracker"
    tier        = 1
    base_weight = 75.0
    timeout     = 30

    def pull(self):
        api_key = os.getenv("ABUSE_CH_API_KEY", "")
        if not api_key:
            raise ValueError("ABUSE_CH_API_KEY not set in .env")

        response = requests.get(
            FEODO_URL,
            headers={"Auth-Key": api_key},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()

        entries = []
        for entry in data:
            ip = entry.get("ip_address", "").strip()
            if not ip:
                continue
            malware = entry.get("malware", "").strip()
            entries.append({
                "type":  "ip",
                "value": ip,
                "suggested_severity": "high",
                "evidence_class": "Infrastructure",
                "description": f"C2 botnet — {malware}" if malware else "C2 botnet IP",
            })

        return entries
