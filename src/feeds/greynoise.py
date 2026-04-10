"""
Intel Pipeline — GreyNoise Enrichment Module
NOT a bulk feed puller. On-demand IP enrichment only.
Community tier: 50 lookups/week. Used during normalisation to add context to IPs.
Requires: GREYNOISE_API_KEY in .env (leave blank for unauthenticated — 10/day)

Usage:
    from src.feeds.greynoise import enrich_ip
    result = enrich_ip("1.2.3.4")
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"


def enrich_ip(ip):
    """
    Query GreyNoise for context on a single IP.

    Returns dict with keys:
        noise (bool)        — IP observed scanning the internet in last 90 days
        riot (bool)         — IP is in RIOT dataset (known benign infrastructure)
        classification (str) — malicious / benign / unknown
        name (str)          — organisation name
        last_seen (str)     — last observed date

    Returns None on failure or if IP not found in GreyNoise dataset.
    """
    api_key = os.getenv("GREYNOISE_API_KEY", "")
    headers = {}
    if api_key:
        headers["key"] = api_key

    try:
        response = requests.get(
            GREYNOISE_URL.format(ip=ip),
            headers=headers,
            timeout=10,
        )

        if response.status_code == 404:
            # IP not in GreyNoise dataset — not an error
            return None

        if response.status_code == 429:
            # Rate limit hit — log and return None gracefully
            print(f"[GreyNoise] Rate limit reached for IP {ip}")
            return None

        response.raise_for_status()
        data = response.json()

        return {
            "noise":          data.get("noise", False),
            "riot":           data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name":           data.get("name", "unknown"),
            "last_seen":      data.get("last_seen"),
        }

    except Exception as e:
        print(f"[GreyNoise] Enrichment failed for {ip}: {e}")
        return None
