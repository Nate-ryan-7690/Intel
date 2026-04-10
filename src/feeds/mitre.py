"""
Intel Pipeline — MITRE ATT&CK Feed Puller
Source: Enterprise ATT&CK STIX JSON via GitHub
No authentication required. No TTL — TTPs are permanent.
Pulls technique IDs (T####.###) and sub-technique IDs.
"""

import requests
from src.feeds.base import BaseFeed

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


class MitreAttackFeed(BaseFeed):
    name        = "MITRE ATT&CK"
    tier        = 1
    base_weight = 85.0
    timeout     = 60    # Large file — allow more time

    def pull(self):
        response = requests.get(MITRE_URL, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()

        entries = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            # Extract ATT&CK ID from external references
            attack_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break

            if not attack_id:
                continue

            entries.append({
                "type":  "ttp",
                "value": attack_id,
                "suggested_severity": "medium",
                "evidence_class": "Behavior",
                "description": obj.get("name"),
            })

        return entries
