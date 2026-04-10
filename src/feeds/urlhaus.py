"""
Intel Pipeline — URLhaus Feed Puller (Abuse.ch)
Source: URLhaus API — recent malicious URLs
Requires: ABUSE_CH_API_KEY in .env
Pulls URLs of active malware distribution and phishing pages.
"""

import os
import requests
from dotenv import load_dotenv
from src.feeds.base import BaseFeed

load_dotenv()

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class URLhausFeed(BaseFeed):
    name        = "URLhaus"
    tier        = 2
    base_weight = 70.0
    timeout     = 30

    def pull(self):
        api_key = os.getenv("ABUSE_CH_API_KEY", "")
        if not api_key:
            raise ValueError("ABUSE_CH_API_KEY not set in .env")

        response = requests.get(
            URLHAUS_URL,
            headers={"Auth-Key": api_key},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok":
            raise ValueError(f"URLhaus API error: {data.get('query_status')}")

        entries = []
        for url_entry in data.get("urls", []):
            url = url_entry.get("url", "").strip()
            if not url:
                continue
            # Only ingest online or unknown status URLs
            if url_entry.get("url_status") == "offline":
                continue
            threat = url_entry.get("threat", "").strip()
            tags   = url_entry.get("tags") or []
            description = threat if threat else None
            if tags:
                tag_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
                description = f"{threat} — {tag_str}" if threat else tag_str

            entries.append({
                "type":  "url",
                "value": url,
                "suggested_severity": "high",
                "evidence_class": "Artifact",
                "description": description,
            })

        return entries
