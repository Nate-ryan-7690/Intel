"""
Intel Pipeline — Decay Engine
Applies step-decay to confidence scores and expires entries that have passed TTL.
Runs on each feed pull cycle and on Flask startup.

Decay model (from document Section 7.4):

  IP / Domain / URL   — Grace: 0-7d | Early: -10 (day 8-21) | Late: -20 (day 22-45) | TTL: 45d
  ASN / Hash          — Grace: 0-30d | Early: -10 (day 31-90) | Late: -20 (day 91-180) | TTL: 180d
  CVE                 — Grace: 0-90d | Early: -10 (day 91-180) | Late: -20 (day 181-365) | TTL: 365d
  TTP                 — Permanent, no decay, no TTL

Decay is applied to all entries regardless of status.
Severity is never modified by the decay system — confidence only.
Expired entries move to status 'expired' — never deleted.
"""

from datetime import datetime, timezone
from src.db.database import get_connection, write_audit

# --- Decay schedule per type ---
# Each entry: (grace_days, early_end_days, early_penalty, late_end_days, late_penalty, ttl_days)
# None for ttl_days = permanent
DECAY_SCHEDULE = {
    "ip":     (7,  21,  10, 45,  20, 45),
    "domain": (7,  21,  10, 45,  20, 45),
    "url":    (7,  21,  10, 45,  20, 45),
    "asn":    (30, 90,  10, 180, 20, 180),
    "hash":   (30, 90,  10, 180, 20, 180),
    "cve":    (90, 180, 10, 365, 20, 365),
    "ttp":    None,   # Permanent — no decay
}

CONFIDENCE_FLOOR = 0.0


def _days_since(iso_timestamp):
    """Return number of days since a given ISO timestamp."""
    then = datetime.fromisoformat(iso_timestamp)
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - then).days


def _calculate_decay(indicator_type, first_seen, current_confidence):
    """
    Calculate the decayed confidence for an entry based on its age.

    Decay penalties are flat per phase — not per day:
      Early phase: -early_penalty applied once when entry enters the phase
      Late phase:  -late_penalty applied once when entry enters the phase
    Maximum total decay = early_penalty + late_penalty before TTL expiry.

    Returns:
        (new_confidence, expired) where expired is True if TTL is reached.
    """
    schedule = DECAY_SCHEDULE.get(indicator_type.lower())

    # TTP — permanent, no decay
    if schedule is None:
        return current_confidence, False

    grace_days, early_end, early_penalty, late_end, late_penalty, ttl_days = schedule
    age = _days_since(first_seen)

    # TTL reached — expire
    if ttl_days and age >= ttl_days:
        return current_confidence, True

    # Grace period — no decay
    if age <= grace_days:
        return current_confidence, False

    # Late decay phase — both penalties applied
    if age > early_end:
        total_penalty = early_penalty + late_penalty
        new_confidence = max(current_confidence - total_penalty, CONFIDENCE_FLOOR)
        return new_confidence, False

    # Early decay phase — early penalty only
    new_confidence = max(current_confidence - early_penalty, CONFIDENCE_FLOOR)
    return new_confidence, False


def run_decay():
    """
    Apply decay to all non-expired, non-rejected entries.
    Expire entries that have passed their TTL.

    Returns a summary dict with counts of decayed and expired entries.
    """
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    entries = conn.execute("""
        SELECT id, type, confidence, first_seen, status
        FROM intel_entries
        WHERE status NOT IN ('expired', 'rejected')
    """).fetchall()

    decayed_count  = 0
    expired_count  = 0

    for entry in entries:
        entry_id   = entry["id"]
        itype      = entry["type"]
        confidence = entry["confidence"]
        first_seen = entry["first_seen"]
        status     = entry["status"]

        new_confidence, should_expire = _calculate_decay(itype, first_seen, confidence)

        if should_expire:
            conn.execute("""
                UPDATE intel_entries SET status = 'expired' WHERE id = ?
            """, (entry_id,))
            write_audit("DECAY_EXPIRED", entry_id=entry_id,
                        detail=f"TTL reached. Final confidence: {confidence}")
            expired_count += 1

        elif abs(new_confidence - confidence) > 0.001:
            conn.execute("""
                UPDATE intel_entries SET confidence = ? WHERE id = ?
            """, (new_confidence, entry_id))
            decayed_count += 1

    conn.commit()
    conn.close()

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
          f"Decay run complete — decayed: {decayed_count}, expired: {expired_count}")

    return {
        "decayed": decayed_count,
        "expired": expired_count,
        "total_checked": len(entries),
    }


if __name__ == "__main__":
    result = run_decay()
    print(result)
