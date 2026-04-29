"""
Intel Pipeline — Normalizer
Maps raw feed data to the canonical intel entry schema before database insertion.
Handles deduplication keys, TLP suggestions, confidence base weights, and TTL calculation.
"""

import hashlib
import json
import os
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

# --- Type severity ceilings (hard caps applied at export time) ---
TYPE_SEVERITY_CEILING = {
    "asn": "medium",
    "ttp": "low",
}

# --- Installed software cache (loaded once per process) ---
_INSTALLED_SW_PATH = os.path.join(
    os.environ.get("USERPROFILE", ""), "Desktop", "SOC", "Config", "installed_software.json"
)
_installed_sw_cache = None


def _get_installed_software():
    global _installed_sw_cache
    if _installed_sw_cache is None:
        try:
            with open(_INSTALLED_SW_PATH, "r", encoding="utf-8") as f:
                _installed_sw_cache = json.load(f).get("software", [])
        except Exception:
            _installed_sw_cache = []
    return _installed_sw_cache


def _find_installed_version(vendor_l, product_l, software_list):
    """Return version string of first installed software matching vendor+product."""
    for sw in software_list:
        name_l = (sw.get("name")      or "").lower()
        pub_l  = (sw.get("publisher") or "").lower()
        if vendor_l in pub_l and product_l in name_l:
            return sw.get("version")
    return None


def _is_version_vulnerable(installed_ver_str, nvd_versions):
    """
    Return True if the installed version falls within any NVD vulnerable CPE match.
    Handles RANGE pattern (versionStart/End fields) and EXPLICIT pattern
    (version encoded in criteria string at field index 5 of the CPE 2.3 URI).
    Fails open (True) on any unparseable version string.
    """
    from packaging.version import Version, InvalidVersion

    if not installed_ver_str:
        return True
    try:
        installed = Version(str(installed_ver_str))
    except InvalidVersion:
        return True  # unparseable installed version — fail open

    for match in nvd_versions:
        vsi = match.get("versionStartIncluding")
        vse = match.get("versionStartExcluding")
        vei = match.get("versionEndIncluding")
        vee = match.get("versionEndExcluding")

        if any([vsi, vse, vei, vee]):
            # RANGE pattern
            in_range = True
            try:
                if vsi and installed < Version(str(vsi)):
                    in_range = False
                if vse and installed <= Version(str(vse)):
                    in_range = False
                if vei and installed > Version(str(vei)):
                    in_range = False
                if vee and installed >= Version(str(vee)):
                    in_range = False
            except InvalidVersion:
                in_range = True  # unparseable bound — fail open
            if in_range:
                return True
        else:
            # EXPLICIT pattern: version at index 5 of cpe:2.3:part:vendor:product:VERSION:...
            criteria = match.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) > 5:
                cpe_ver = parts[5]
                if cpe_ver not in ("*", "-", ""):
                    try:
                        if installed == Version(str(cpe_ver)):
                            return True
                    except InvalidVersion:
                        if str(installed_ver_str) == cpe_ver:
                            return True

    return False


def _cve_gate(vendor, product, nvd_versions_raw, suggested_severity):
    """
    Version-aware severity gate for CVE indicators.
    Can only DOWNGRADE severity (to 'medium') — never raises it.
    Fails open (returns suggested_severity unchanged) when enrichment data is
    absent, inconclusive, or the installed version cannot be determined.
    """
    fallback = suggested_severity

    if not vendor or not product:
        return fallback

    vendor_l  = vendor.lower().strip()
    product_l = product.lower().strip()

    # Microsoft/Windows: every Windows endpoint is always affected — skip version check
    if vendor_l == "microsoft" and product_l.startswith("windows"):
        return fallback

    # nvd_versions IS NULL → enrichment not yet run, fail open
    if nvd_versions_raw is None:
        return fallback

    if isinstance(nvd_versions_raw, str):
        try:
            nvd_versions = json.loads(nvd_versions_raw)
        except Exception:
            return fallback
    else:
        nvd_versions = nvd_versions_raw

    # nvd_versions = [] → no range data or hardcoded match, fail open
    if not nvd_versions:
        return fallback

    # Look up installed version
    software      = _get_installed_software()
    installed_ver = _find_installed_version(vendor_l, product_l, software)

    if installed_ver is None:
        return fallback  # product absent from software list — fail open

    if _is_version_vulnerable(installed_ver, nvd_versions):
        return fallback  # installed version is in a vulnerable range — keep severity

    # Installed version is outside all vulnerable ranges — downgrade, but never raise
    # (analyst may have already set a lower severity deliberately)
    medium_idx = SEVERITY_VALUES.index("medium")
    if SEVERITY_VALUES.index(fallback) > medium_idx:
        return "medium"
    return fallback


def compute_effective_severity(indicator_type, suggested_severity, nvd_versions=None,
                               vendor=None, product=None):
    """
    Compute export-time effective severity by applying type ceilings and the CVE
    version gate.

    Type ceilings:  ASN → max medium  |  TTP → max low
    CVE gate:       checks nvd_versions against installed_software.json;
                    downgrades to 'medium' if installed version is outside all
                    vulnerable ranges; fails open on missing data.

    Args:
        indicator_type (str):     e.g. 'cve', 'ip', 'asn', 'ttp'
        suggested_severity (str): Stored suggested_severity from the database.
        nvd_versions:             nvd_versions column value (str JSON or list).
        vendor (str):             affected_vendor field (CVE only).
        product (str):            affected_product field (CVE only).

    Returns:
        str: Effective severity from SEVERITY_VALUES.
    """
    severity = (suggested_severity or "low").lower()

    # Apply type ceiling
    ceiling = TYPE_SEVERITY_CEILING.get(indicator_type)
    if ceiling and SEVERITY_VALUES.index(severity) > SEVERITY_VALUES.index(ceiling):
        severity = ceiling

    # CVE version gate (only downgrade, never raise)
    if indicator_type == "cve":
        severity = _cve_gate(vendor, product, nvd_versions, severity)

    return severity


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
        "affected_vendor":    raw.get("affected_vendor"),
        "affected_product":   raw.get("affected_product"),
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
        "affected_vendor":    None,
        "affected_product":   None,
    }
