"""
Intel Pipeline — Normalizer
Maps raw feed data to the canonical intel entry schema before database insertion.
Handles deduplication keys, TLP suggestions, confidence base weights, and TTL calculation.
"""

import hashlib
import json
from datetime import datetime, timezone, timedelta

# --- Severity enum (allowed values only) ---
SEVERITY_VALUES = ["info", "low", "medium", "high", "critical"]

# --- TLP suggestions by source tier ---
TLP_BY_TIER = {
    1: "TLP:WHITE",
    2: "TLP:GREEN",
    3: "TLP:AMBER",
}

# --- TTL in days by indicator type (None = no expiry) ---
TTL_BY_TYPE = {
    "ip":     45,
    "domain": 45,
    "url":    45,
    "asn":    180,
    "hash":   180,
    "cve":    365,
    "ttp":    None,
}

# --- Evidence class mapping by indicator type ---
EVIDENCE_CLASS_BY_TYPE = {
    "ip":     "Infrastructure",
    "domain": "Infrastructure",
    "url":    "Artifact",
    "asn":    "Infrastructure",
    "hash":   "Artifact",
    "cve":    "Vulnerability",
    "ttp":    "Behavior",
}


def normalize_value(indicator_type, value):
    """
    Apply type-specific normalization to the indicator value.
    Returns the normalized value string.
    """
    if indicator_type == "domain":
        value = value.lower().strip()
        if value.startswith("www."):
            value = value[4:]
        return value

    if indicator_type == "url":
        # Lowercase scheme and host, strip query strings, key on host + path
        try:
            from urllib.parse import urlparse
            parsed = urlparse(value.lower().strip())
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        except Exception:
            return value.lower().strip()

    if indicator_type == "cve":
        return value.upper().strip()

    if indicator_type == "asn":
        # Normalize to AS + number format
        value = value.strip().upper()
        if not value.startswith("AS"):
            value = f"AS{value}"
        return value

    if indicator_type == "ttp":
        return value.upper().strip()

    return value.strip()


def get_dedup_key(indicator_type, value):
    """
    Return the deduplication key for this indicator.
    This is what determines whether an incoming entry matches an existing one.
    """
    normalized = normalize_value(indicator_type, value)
    return (indicator_type.lower(), normalized)


def calculate_expires_at(indicator_type, first_seen):
    """
    Calculate expiry timestamp based on indicator type TTL.
    Returns ISO string or None for permanent indicators (TTP).
    """
    ttl_days = TTL_BY_TYPE.get(indicator_type.lower())
    if ttl_days is None:
        return None
    if isinstance(first_seen, str):
        first_seen = datetime.fromisoformat(first_seen)
    expires = first_seen + timedelta(days=ttl_days)
    return expires.isoformat()


def suggest_tlp(tier):
    """Return suggested TLP based on source tier."""
    return TLP_BY_TIER.get(tier, "TLP:AMBER")


def suggest_severity(feed_name, indicator_type):
    """
    Suggest severity based on feed source and indicator type.
    Conservative defaults — analyst always assigns final value.
    """
    high_authority = ["CISA KEV", "Spamhaus ASN-DROP", "Feodo Tracker"]
    strong_operational = ["MalwareBazaar", "ThreatFox", "URLhaus"]

    if feed_name in high_authority:
        return "high"
    if feed_name in strong_operational:
        if indicator_type in ("hash", "ip"):
            return "high"
        return "medium"
    if indicator_type == "cve":
        return "medium"
    if indicator_type == "ttp":
        return "medium"
    return "low"


def normalize_entry(raw, feed_name, tier, base_weight):
    """
    Map a raw feed entry to the canonical intel entry schema.

    Args:
        raw (dict): Raw data from feed puller. Must contain 'type' and 'value'.
        feed_name (str): Name of the source feed.
        tier (int): Source tier (1, 2, or 3).
        base_weight (float): Base confidence weight for this source.

    Returns:
        dict: Normalized entry ready for database insertion or update.
    """
    indicator_type = raw.get("type", "").lower().strip()
    raw_value = raw.get("value", "").strip()

    if not indicator_type or not raw_value:
        raise ValueError(f"normalize_entry: missing type or value in raw entry: {raw}")

    if indicator_type not in TTL_BY_TYPE:
        raise ValueError(f"normalize_entry: unsupported indicator type '{indicator_type}'")

    normalized_value = normalize_value(indicator_type, raw_value)
    now = datetime.now(timezone.utc).isoformat()

    return {
        "type":               indicator_type,
        "value":              normalized_value,
        "evidence_class":     raw.get("evidence_class") or EVIDENCE_CLASS_BY_TYPE.get(indicator_type, "Context"),
        "confidence":         base_weight,
        "suggested_severity": raw.get("suggested_severity") or suggest_severity(feed_name, indicator_type),
        "approved_severity":  None,
        "suggested_tlp":      suggest_tlp(tier),
        "approved_tlp":       None,
        "source_list":        json.dumps([feed_name]),
        "source_count":       1,
        "first_seen":         now,
        "last_seen":          now,
        "ttl":                TTL_BY_TYPE.get(indicator_type),
        "expires_at":         calculate_expires_at(indicator_type, now),
        "lane":               "automated",
        "status":             "pending",
        "approved_at":        None,
        "approved_by":        None,
        "last_reviewed":      None,
        "engine_action":      None,
        "description":        raw.get("description"),
    }


def normalize_human_entry(value, indicator_type, source_label, source_tier, base_weight, suggested_severity=None):
    """
    Normalize a manually submitted human input lane entry.

    Args:
        value (str): The indicator value.
        indicator_type (str): The indicator type.
        source_label (str): Human-readable source description (e.g. 'SANS email').
        source_tier (int): Tier assigned based on source type selection.
        base_weight (float): Base weight from source type dropdown.
        suggested_severity (str): Optional — analyst may suggest at submission time.

    Returns:
        dict: Normalized entry ready for database insertion.
    """
    indicator_type = indicator_type.lower().strip()
    normalized_value = normalize_value(indicator_type, value)
    now = datetime.now(timezone.utc).isoformat()

    return {
        "type":               indicator_type,
        "value":              normalized_value,
        "evidence_class":     EVIDENCE_CLASS_BY_TYPE.get(indicator_type, "Context"),
        "confidence":         base_weight,
        "suggested_severity": suggested_severity or suggest_severity(source_label, indicator_type),
        "approved_severity":  None,
        "suggested_tlp":      suggest_tlp(source_tier),
        "approved_tlp":       None,
        "source_list":        json.dumps([source_label]),
        "source_count":       1,
        "first_seen":         now,
        "last_seen":          now,
        "ttl":                TTL_BY_TYPE.get(indicator_type),
        "expires_at":         calculate_expires_at(indicator_type, now),
        "lane":               "human",
        "status":             "pending",
        "approved_at":        None,
        "approved_by":        None,
        "last_reviewed":      None,
        "engine_action":      None,
    }
