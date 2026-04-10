"""
Intel Pipeline — Ingest Layer
Handles insertion of new entries and updates to existing ones.
Applies corroboration, reinforcement confidence logic, and triggers re-review
when an approved entry is updated by a feed.
"""

import json
from datetime import datetime, timezone

from src.db.database import get_connection, write_audit
from src.normalizer import get_dedup_key, normalize_value

# --- Confidence config ---
CORROBORATION_INDEPENDENT   = 10   # New independent source
CORROBORATION_SAME_SOURCE   = 3    # Same source seen again
REINFORCEMENT_LOW           = 3
REINFORCEMENT_MEDIUM        = 5
REINFORCEMENT_HIGH          = 8
CONFIDENCE_CAP              = 100
NICHE_CAP                   = 60   # Tier 3 cap until Tier 1 corroborates

# --- Fields that force re-review when changed ---
REREVIEW_FIELDS = {"suggested_severity", "evidence_class", "confidence", "ttl", "expires_at"}

# --- Fields that are informational only (no re-review) ---
INFORMATIONAL_FIELDS = {"source_list", "source_count", "last_seen"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _is_tier1(feed_name):
    """Return True if the feed is a Tier 1 trusted source."""
    tier1 = {"MITRE ATT&CK", "CISA KEV", "Spamhaus ASN-DROP", "MalwareBazaar", "Feodo Tracker"}
    return feed_name in tier1


def _apply_niche_cap(confidence, entry_id, conn):
    """
    Apply the 60% niche cap if no Tier 1 source has corroborated this entry.
    Cap is lifted once a Tier 1 source appears in source_list.
    """
    row = conn.execute(
        "SELECT source_list FROM intel_entries WHERE id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return min(confidence, NICHE_CAP)

    sources = json.loads(row["source_list"])
    tier1_sources = {"MITRE ATT&CK", "CISA KEV", "Spamhaus ASN-DROP", "MalwareBazaar", "Feodo Tracker"}
    has_tier1 = any(s in tier1_sources for s in sources)

    if has_tier1:
        return min(confidence, CONFIDENCE_CAP)
    return min(confidence, NICHE_CAP)


def _calculate_reinforcement(feed_name, existing_sources):
    """
    Determine confidence bonus and whether the source is new or repeat.

    Rules:
      - New independent source: +10
      - Same source repeat pull: no bonus, last_seen update only

    Returns (bonus, is_new_source).
    """
    if feed_name not in existing_sources:
        return CORROBORATION_INDEPENDENT, True
    else:
        return 0, False


def _build_diff(existing, incoming):
    """
    Compare existing entry fields against incoming normalised entry.
    Returns (rereview_changes, informational_changes) as dicts of {field: (old, new)}.
    """
    rereview = {}
    informational = {}

    for field in REREVIEW_FIELDS:
        old_val = existing[field] if field in existing.keys() else None
        new_val = incoming.get(field)
        if str(old_val) != str(new_val):
            rereview[field] = {"old": old_val, "new": new_val}

    for field in INFORMATIONAL_FIELDS:
        old_val = existing[field] if field in existing.keys() else None
        new_val = incoming.get(field)
        if str(old_val) != str(new_val):
            informational[field] = {"old": old_val, "new": new_val}

    return rereview, informational


def ingest_entry(normalized_entry, feed_name, tier):
    """
    Insert a new entry or update an existing one.

    - New entry: inserted with status 'pending'.
    - Existing pending entry: confidence updated, source list merged.
    - Existing approved entry: diff calculated, status set to 'pending_review'
      if re-review fields changed.

    Args:
        normalized_entry (dict): Output from normalizer.normalize_entry().
        feed_name (str): Name of the source feed.
        tier (int): Source tier.

    Returns:
        str: 'inserted', 'updated_pending', 'updated_rereview', 'updated_informational', 'no_change'
    """
    conn = get_connection()
    indicator_type = normalized_entry["type"]
    value = normalized_entry["value"]

    existing = conn.execute(
        "SELECT * FROM intel_entries WHERE type = ? AND value = ?",
        (indicator_type, value)
    ).fetchone()

    now = _now()

    # --- New entry ---
    if existing is None:
        conn.execute("""
            INSERT INTO intel_entries (
                type, value, evidence_class, confidence,
                suggested_severity, approved_severity,
                suggested_tlp, approved_tlp,
                source_list, source_count,
                first_seen, last_seen,
                ttl, expires_at, lane, status,
                approved_at, approved_by, last_reviewed, engine_action,
                description
            ) VALUES (
                :type, :value, :evidence_class, :confidence,
                :suggested_severity, :approved_severity,
                :suggested_tlp, :approved_tlp,
                :source_list, :source_count,
                :first_seen, :last_seen,
                :ttl, :expires_at, :lane, :status,
                :approved_at, :approved_by, :last_reviewed, :engine_action,
                :description
            )
        """, normalized_entry)
        conn.commit()

        entry_id = conn.execute(
            "SELECT id FROM intel_entries WHERE type = ? AND value = ?",
            (indicator_type, value)
        ).fetchone()["id"]

        write_audit("INGEST_NEW", entry_id=entry_id, detail=f"Source: {feed_name}")
        conn.close()
        return "inserted"

    # --- Existing entry ---
    entry_id = existing["id"]
    current_status = existing["status"]

    # --- Expired entry re-observation: reset to base weight, back to pending ---
    if current_status == "expired":
        base_weight_row = conn.execute(
            "SELECT base_weight FROM feed_config WHERE feed_name = ?", (feed_name,)
        ).fetchone()
        reset_confidence = base_weight_row["base_weight"] if base_weight_row else normalized_entry.get("confidence", 50)

        conn.execute("""
            UPDATE intel_entries SET
                confidence      = ?,
                source_list     = ?,
                source_count    = ?,
                first_seen      = ?,
                last_seen       = ?,
                status          = 'pending',
                approved_at     = NULL,
                approved_by     = NULL,
                last_reviewed   = NULL,
                suggested_severity = COALESCE(?, suggested_severity),
                evidence_class  = COALESCE(?, evidence_class),
                description     = COALESCE(?, description)
            WHERE id = ?
        """, (
            reset_confidence,
            json.dumps([feed_name]),
            1,
            now,
            now,
            normalized_entry.get("suggested_severity"),
            normalized_entry.get("evidence_class"),
            normalized_entry.get("description"),
            entry_id
        ))
        conn.commit()
        write_audit("INGEST_EXPIRED_RESET", entry_id=entry_id,
                    detail=f"Source: {feed_name} | Confidence reset to {reset_confidence}")
        conn.close()
        return "inserted"  # treat as new for summary counting

    existing_sources = json.loads(existing["source_list"])
    bonus, is_new_source = _calculate_reinforcement(feed_name, existing_sources)

    # Update source list
    if is_new_source:
        existing_sources.append(feed_name)
    updated_sources = json.dumps(existing_sources)
    updated_source_count = len(existing_sources)

    # Update confidence
    new_confidence = existing["confidence"] + bonus
    if tier == 3:
        new_confidence = _apply_niche_cap(new_confidence, entry_id, conn)
    elif _is_tier1(feed_name):
        # Tier 1 corroboration — remove niche cap, recalculate without it
        new_confidence = min(new_confidence, CONFIDENCE_CAP)
    else:
        new_confidence = min(new_confidence, CONFIDENCE_CAP)

    # Build diff for re-review check
    rereview_changes, informational_changes = _build_diff(existing, normalized_entry)

    # Determine new status
    if current_status == "approved" and rereview_changes:
        new_status = "pending_review"
        result = "updated_rereview"
    elif current_status == "approved" and informational_changes:
        new_status = "approved"
        result = "updated_informational"
    elif current_status in ("pending", "pending_review"):
        new_status = current_status
        result = "updated_pending"
    else:
        new_status = current_status
        result = "no_change"

    conn.execute("""
        UPDATE intel_entries SET
            confidence      = ?,
            source_list     = ?,
            source_count    = ?,
            last_seen       = ?,
            status          = ?,
            suggested_severity = COALESCE(?, suggested_severity),
            evidence_class  = COALESCE(?, evidence_class),
            description     = COALESCE(?, description)
        WHERE id = ?
    """, (
        new_confidence,
        updated_sources,
        updated_source_count,
        now,
        new_status,
        normalized_entry.get("suggested_severity"),
        normalized_entry.get("evidence_class"),
        normalized_entry.get("description"),
        entry_id
    ))
    conn.commit()

    diff_detail = json.dumps({"rereview": rereview_changes, "informational": informational_changes})
    write_audit(f"INGEST_UPDATE_{result.upper()}", entry_id=entry_id,
                detail=f"Source: {feed_name} | Diff: {diff_detail}")
    conn.close()
    return result


def ingest_batch(normalized_entries, feed_name, tier):
    """
    Ingest a list of normalised entries from a single feed pull.
    Returns a summary dict with counts per result type.
    """
    summary = {
        "inserted": 0,
        "updated_pending": 0,
        "updated_rereview": 0,
        "updated_informational": 0,
        "no_change": 0,
        "errors": 0,
    }

    for entry in normalized_entries:
        try:
            result = ingest_entry(entry, feed_name, tier)
            summary[result] += 1
        except Exception as e:
            summary["errors"] += 1
            print(f"[INGEST ERROR] {feed_name} | {entry.get('value', '?')} | {e}")

    return summary
