"""
Intel Pipeline — Export Module
Generates JSON exports of the approved indicator pool with SHA256 sidecar.
Retains last 5 snapshots for rollback. Logs all export and rollback actions to audit log.

Export format:
    {
        "schema_version": "1.0",
        "exported_at": "<ISO timestamp>",
        "entry_count": <int>,
        "tlp": "<most restrictive TLP in export>",
        "indicators": [ ... ]
    }

SHA256 sidecar: <filename>.sha256 containing the hex digest of the JSON file.
"""

import json
import hashlib
import os
from datetime import datetime, timezone

from src.db.database import get_connection, write_audit
from src.normalizer import compute_effective_severity

# --- Config ---
ROOT_PATH      = os.path.join(os.environ["USERPROFILE"], "Desktop", "Intel")
EXPORTS_DIR    = os.path.join(ROOT_PATH, "Exports")
SCHEMA_VERSION = "1.1"
MAX_SNAPSHOTS  = 5

# TLP precedence — higher index = more restrictive
TLP_ORDER = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]


def _most_restrictive_tlp(tlp_values):
    """Return the most restrictive TLP from a list of TLP strings."""
    highest = 0
    for tlp in tlp_values:
        try:
            idx = TLP_ORDER.index(tlp)
            if idx > highest:
                highest = idx
        except ValueError:
            pass
    return TLP_ORDER[highest]


def _sha256_of_file(filepath):
    """Compute SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _prune_snapshots():
    """
    Remove oldest export snapshots beyond MAX_SNAPSHOTS.
    Deletes both the JSON and .sha256 sidecar files.
    Updates the export_snapshots table.
    """
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, filename FROM export_snapshots
        ORDER BY exported_at DESC
    """).fetchall()

    if len(rows) <= MAX_SNAPSHOTS:
        conn.close()
        return

    to_delete = rows[MAX_SNAPSHOTS:]
    for row in to_delete:
        # Remove files
        json_path = os.path.join(EXPORTS_DIR, row["filename"])
        sha256_path = json_path + ".sha256"
        for path in (json_path, sha256_path):
            if os.path.exists(path):
                os.remove(path)

        conn.execute("DELETE FROM export_snapshots WHERE id = ?", (row["id"],))

    conn.commit()
    conn.close()


def generate_export(export_type="standard", performed_by=None):
    """
    Generate a full export of all approved indicators.
    Writes JSON + SHA256 sidecar to Exports/.
    Registers snapshot in database. Prunes oldest if > MAX_SNAPSHOTS.

    Args:
        export_type (str): 'standard' or 'urgent'
        performed_by (str): Analyst identifier (optional)

    Returns:
        dict: Export result with filename, sha256, entry_count, tlp, path.
    """
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            type, value, evidence_class, confidence,
            suggested_severity, approved_severity, approved_tlp, suggested_tlp,
            source_list, source_count,
            first_seen, last_seen, expires_at,
            engine_action, lane, approved_at, approved_by,
            description, affected_vendor, affected_product, nvd_versions
        FROM intel_entries
        WHERE status = 'approved'
        ORDER BY approved_at DESC
    """).fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    exported_at = now.isoformat()

    # Build indicator list
    indicators = []
    tlp_values = []

    for row in rows:
        # Use approved_tlp if set, fall back to suggested_tlp
        tlp = row["approved_tlp"] or row["suggested_tlp"] or "TLP:GREEN"
        tlp_values.append(tlp)

        # Severity: always run type ceilings + CVE gate so the export reflects current
        # enrichment data. approved_severity is used as the base (analyst's assessment)
        # if set, otherwise falls back to suggested_severity. Gate can only downgrade —
        # it will never raise severity above what the analyst or feed assigned.
        base_severity = row["approved_severity"] or row["suggested_severity"]
        severity = compute_effective_severity(
            row["type"],
            base_severity,
            nvd_versions=row["nvd_versions"],
            vendor=row["affected_vendor"],
            product=row["affected_product"],
        )

        indicators.append({
            "type":             row["type"],
            "value":            row["value"],
            "evidence_class":   row["evidence_class"],
            "confidence":       row["confidence"],
            "severity":         severity,
            "tlp":              tlp,
            "engine_action":    row["engine_action"],
            "source_list":      json.loads(row["source_list"] or "[]"),
            "source_count":     row["source_count"],
            "first_seen":       row["first_seen"],
            "last_seen":        row["last_seen"],
            "expires_at":       row["expires_at"],
            "lane":             row["lane"],
            "approved_at":      row["approved_at"],
            "approved_by":      row["approved_by"],
            "description":      row["description"],
            "affected_vendor":  row["affected_vendor"],
            "affected_product": row["affected_product"],
        })

    export_tlp = _most_restrictive_tlp(tlp_values) if tlp_values else "TLP:WHITE"

    export_data = {
        "schema_version": SCHEMA_VERSION,
        "exported_at":    exported_at,
        "entry_count":    len(indicators),
        "tlp":            export_tlp,
        "export_type":    export_type,
        "indicators":     indicators,
    }

    # Write JSON
    filename = f"intel_export_{now.strftime('%Y%m%d_%H%M%S_%f')}_{export_type}.json"
    json_path = os.path.join(EXPORTS_DIR, filename)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    # Write SHA256 sidecar
    sha256_digest = _sha256_of_file(json_path)
    sha256_path = json_path + ".sha256"
    with open(sha256_path, "w", encoding="utf-8") as f:
        f.write(f"{sha256_digest}  {filename}\n")

    # Register snapshot in database
    conn = get_connection()
    conn.execute("""
        INSERT INTO export_snapshots
            (filename, sha256, exported_at, entry_count, tlp, export_type, schema_version)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (filename, sha256_digest, exported_at, len(indicators),
          export_tlp, export_type, SCHEMA_VERSION))
    conn.commit()
    conn.close()

    # Prune old snapshots
    _prune_snapshots()

    # Audit log
    write_audit(
        "EXPORT_GENERATED",
        detail=f"Type: {export_type} | Entries: {len(indicators)} | TLP: {export_tlp} | File: {filename}",
        performed_by=performed_by,
    )

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
          f"Export generated — {len(indicators)} indicators | {filename}")

    return {
        "filename":    filename,
        "sha256":      sha256_digest,
        "entry_count": len(indicators),
        "tlp":         export_tlp,
        "path":        json_path,
        "exported_at": exported_at,
    }


def rollback_to_snapshot(snapshot_id, performed_by=None):
    """
    Restore a previous export snapshot as the active export.
    Copies the selected snapshot files to a new export with type 'rollback'.
    Does not modify the database — rollback is a new export pointing to old data.

    Args:
        snapshot_id (int): ID from export_snapshots table.
        performed_by (str): Analyst identifier for audit log.

    Returns:
        dict: Rollback result with filename and sha256, or error string.
    """
    conn = get_connection()
    snapshot = conn.execute(
        "SELECT * FROM export_snapshots WHERE id = ?", (snapshot_id,)
    ).fetchone()
    conn.close()

    if not snapshot:
        return {"error": f"Snapshot ID {snapshot_id} not found."}

    source_path = os.path.join(EXPORTS_DIR, snapshot["filename"])
    if not os.path.exists(source_path):
        return {"error": f"Snapshot file missing: {snapshot['filename']}"}

    # Verify hash before rollback
    current_hash = _sha256_of_file(source_path)
    if current_hash != snapshot["sha256"]:
        write_audit("ROLLBACK_HASH_MISMATCH", detail=f"Snapshot {snapshot_id} hash mismatch — rollback aborted.")
        return {"error": "SHA256 verification failed — snapshot may be tampered. Rollback aborted."}

    # Write rollback copy as a new export
    now = datetime.now(timezone.utc)
    rollback_filename = f"intel_export_{now.strftime('%Y%m%d_%H%M%S_%f')}_rollback.json"
    rollback_path = os.path.join(EXPORTS_DIR, rollback_filename)

    with open(source_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["export_type"] = "rollback"
    data["exported_at"] = now.isoformat()

    with open(rollback_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    rollback_sha256 = _sha256_of_file(rollback_path)
    sha256_path = rollback_path + ".sha256"
    with open(sha256_path, "w", encoding="utf-8") as f:
        f.write(f"{rollback_sha256}  {rollback_filename}\n")

    # Register rollback as new snapshot
    conn = get_connection()
    conn.execute("""
        INSERT INTO export_snapshots
            (filename, sha256, exported_at, entry_count, tlp, export_type, schema_version)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (rollback_filename, rollback_sha256, now.isoformat(),
          snapshot["entry_count"], snapshot["tlp"], "rollback", snapshot["schema_version"]))
    conn.commit()
    conn.close()

    _prune_snapshots()

    write_audit(
        "ROLLBACK_EXECUTED",
        detail=f"Rolled back to snapshot {snapshot_id} ({snapshot['filename']}) | New file: {rollback_filename}",
        performed_by=performed_by,
    )

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
          f"Rollback complete — restored from snapshot {snapshot_id} to {rollback_filename}")

    return {
        "filename":    rollback_filename,
        "sha256":      rollback_sha256,
        "entry_count": snapshot["entry_count"],
        "source_snapshot": snapshot_id,
    }


def verify_export(filename):
    """
    Verify the SHA256 hash of an export file against its sidecar.

    Args:
        filename (str): Export filename (not full path).

    Returns:
        dict: {'valid': bool, 'expected': str, 'actual': str}
    """
    json_path   = os.path.join(EXPORTS_DIR, filename)
    sha256_path = json_path + ".sha256"

    if not os.path.exists(json_path):
        return {"valid": False, "error": "Export file not found."}
    if not os.path.exists(sha256_path):
        return {"valid": False, "error": "SHA256 sidecar not found."}

    with open(sha256_path, "r", encoding="utf-8") as f:
        expected = f.read().strip().split()[0]

    actual = _sha256_of_file(json_path)
    valid  = expected == actual

    return {"valid": valid, "expected": expected, "actual": actual, "filename": filename}


def list_snapshots():
    """Return all retained export snapshots ordered newest first."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, filename, sha256, exported_at, entry_count, tlp, export_type
        FROM export_snapshots
        ORDER BY exported_at DESC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]
