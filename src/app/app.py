"""
Intel Pipeline — Flask Dashboard
Single-page analyst interface. Port 6001. Localhost only.

Layout (top to bottom):
  1. Feed health strip
  2. Pull All Feeds + individual feed buttons
  3. Approval queue (pending_review first, then pending)
  4. Search
  5. Manual entry form
"""

import os
import sys
import json
from datetime import datetime, timezone
from flask import Flask, render_template_string, request, jsonify

# Ensure project root is on path when run from src/app/
ROOT_PATH = os.path.join(os.environ["USERPROFILE"], "Desktop", "Intel")
sys.path.insert(0, ROOT_PATH)

from src.db.database import get_connection, write_audit, init_db, seed_feed_config
from src.feeds.runner import run_all_feeds, run_single_feed, ALL_FEEDS
from src.decay import run_decay
from src.exporter import generate_export, list_snapshots, rollback_to_snapshot
from src.normalizer import normalize_human_entry, SEVERITY_VALUES

app = Flask(__name__)

# --- Human source weights (document Section 7.2) ---
HUMAN_SOURCES = {
    "strong_reference": {"label": "Strong Reference", "weight": 60, "tier": 3},
    "weak_reference":   {"label": "Weak Reference",   "weight": 45, "tier": 3},
    "blog_forum":       {"label": "Blog / Forum",      "weight": 45, "tier": 3},
    "social":           {"label": "Social / Reddit",   "weight": 40, "tier": 3},
}

INDICATOR_TYPES  = ["ip", "domain", "hash", "cve", "asn", "ttp", "url"]
ENGINE_ACTIONS   = ["Alert", "Block", "Log"]
TLP_VALUES       = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]
FEED_NAMES       = [f.name for f in ALL_FEEDS]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat()


def _get_feed_health():
    """Return latest pull status per feed."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT feed_name, status, pull_at, indicators_new, indicators_updated, error_message
        FROM feed_health
        WHERE id IN (
            SELECT MAX(id) FROM feed_health GROUP BY feed_name
        )
        ORDER BY feed_name
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


QUEUE_PAGE_SIZE = 50

def _get_queue(type_filter=None, page=1):
    """
    Return pending_review first, then pending.
    Supports optional type filter and pagination.
    Returns (entries, total_count, total_pages).
    """
    conn = get_connection()

    where = "WHERE status IN ('pending', 'pending_review')"
    params = []
    if type_filter:
        where += " AND type = ?"
        params.append(type_filter)

    total = conn.execute(
        f"SELECT COUNT(*) FROM intel_entries {where}", params
    ).fetchone()[0]

    offset = (page - 1) * QUEUE_PAGE_SIZE
    rows = conn.execute(f"""
        SELECT id, type, value, evidence_class, confidence,
               suggested_severity, approved_severity,
               suggested_tlp, approved_tlp,
               source_list, source_count, status,
               first_seen, last_seen, expires_at, lane,
               approved_at, engine_action, description
        FROM intel_entries
        {where}
        ORDER BY
            CASE status WHEN 'pending_review' THEN 0 ELSE 1 END,
            first_seen DESC
        LIMIT ? OFFSET ?
    """, params + [QUEUE_PAGE_SIZE, offset]).fetchall()

    conn.close()
    import math
    total_pages = max(1, math.ceil(total / QUEUE_PAGE_SIZE))
    return [dict(r) for r in rows], total, total_pages


def _get_entry(entry_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM intel_entries WHERE id = ?", (entry_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _get_notes(entry_id):
    conn = get_connection()
    rows = conn.execute("""
        SELECT note, created_at, created_by
        FROM analyst_notes
        WHERE entry_id = ?
        ORDER BY created_at ASC
    """, (entry_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _add_note(entry_id, note_text, created_by=None):
    conn = get_connection()
    conn.execute("""
        INSERT INTO analyst_notes (entry_id, note, created_at, created_by)
        VALUES (?, ?, ?, ?)
    """, (entry_id, note_text.strip(), _now(), created_by))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    feed_health  = _get_feed_health()
    type_filter  = request.args.get("type_filter", "").strip()
    page         = max(1, int(request.args.get("page", 1)))
    queue, total, total_pages = _get_queue(type_filter or None, page)
    snapshots    = list_snapshots()
    pending_review_count = sum(1 for e in queue if e["status"] == "pending_review")
    pending_count        = sum(1 for e in queue if e["status"] == "pending")

    return render_template_string(
        HTML_TEMPLATE,
        feed_health=feed_health,
        queue=queue,
        snapshots=snapshots,
        pending_review_count=pending_review_count,
        pending_count=pending_count,
        total=total,
        total_pages=total_pages,
        current_page=page,
        type_filter=type_filter,
        feed_names=FEED_NAMES,
        indicator_types=INDICATOR_TYPES,
        severity_values=SEVERITY_VALUES,
        engine_actions=ENGINE_ACTIONS,
        tlp_values=TLP_VALUES,
        human_sources=HUMAN_SOURCES,
    )


# ---------------------------------------------------------------------------
# Feed pull routes
# ---------------------------------------------------------------------------

@app.route("/pull/all", methods=["POST"])
def pull_all():
    results = run_all_feeds()
    run_decay()
    return jsonify(results)


@app.route("/pull/<feed_name>", methods=["POST"])
def pull_one(feed_name):
    result = run_single_feed(feed_name)
    run_decay()
    return jsonify(result)


@app.route("/feed_health")
def feed_health():
    return jsonify(_get_feed_health())


# ---------------------------------------------------------------------------
# Queue and entry routes
# ---------------------------------------------------------------------------

@app.route("/queue")
def queue():
    type_filter = request.args.get("type_filter", "").strip() or None
    page        = max(1, int(request.args.get("page", 1)))
    entries, total, total_pages = _get_queue(type_filter, page)
    return jsonify({"entries": entries, "total": total, "total_pages": total_pages, "page": page})


@app.route("/entry/<int:entry_id>")
def entry_detail(entry_id):
    entry = _get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404
    notes = _get_notes(entry_id)
    entry["notes"] = notes
    entry["source_list"] = json.loads(entry.get("source_list") or "[]")
    return jsonify(entry)


@app.route("/approve/<int:entry_id>", methods=["POST"])
def approve(entry_id):
    data             = request.get_json()
    approved_severity = data.get("approved_severity", "").strip()
    approved_tlp      = data.get("approved_tlp", "").strip()
    engine_action     = data.get("engine_action", "").strip()
    note_text         = data.get("note", "").strip()

    if approved_severity not in SEVERITY_VALUES:
        return jsonify({"error": "Invalid severity value."}), 400
    if approved_tlp not in TLP_VALUES:
        return jsonify({"error": "Invalid TLP value."}), 400
    if engine_action not in ENGINE_ACTIONS:
        return jsonify({"error": "Invalid engine action."}), 400

    conn = get_connection()
    conn.execute("""
        UPDATE intel_entries SET
            status            = 'approved',
            approved_severity = ?,
            approved_tlp      = ?,
            engine_action     = ?,
            approved_at       = ?,
            last_reviewed     = ?
        WHERE id = ?
    """, (approved_severity, approved_tlp, engine_action, _now(), _now(), entry_id))
    conn.commit()
    conn.close()

    if note_text:
        _add_note(entry_id, note_text)

    write_audit("APPROVED", entry_id=entry_id,
                detail=f"Severity: {approved_severity} | TLP: {approved_tlp} | Action: {engine_action}")
    return jsonify({"status": "approved"})


@app.route("/reject/<int:entry_id>", methods=["POST"])
def reject(entry_id):
    data      = request.get_json()
    note_text = data.get("note", "").strip()

    if not note_text:
        return jsonify({"error": "A note is required when rejecting an entry."}), 400

    conn = get_connection()
    conn.execute("""
        UPDATE intel_entries SET
            status        = 'rejected',
            last_reviewed = ?
        WHERE id = ?
    """, (_now(), entry_id))
    conn.commit()
    conn.close()

    _add_note(entry_id, f"[REJECTION] {note_text}")
    write_audit("REJECTED", entry_id=entry_id, detail=note_text)
    return jsonify({"status": "rejected"})


@app.route("/note/<int:entry_id>", methods=["POST"])
def add_note(entry_id):
    data      = request.get_json()
    note_text = data.get("note", "").strip()
    if not note_text:
        return jsonify({"error": "Note cannot be empty."}), 400
    _add_note(entry_id, note_text)
    write_audit("NOTE_ADDED", entry_id=entry_id)
    return jsonify({"status": "note added"})


# ---------------------------------------------------------------------------
# Search route
# ---------------------------------------------------------------------------

@app.route("/search")
def search():
    query        = request.args.get("q", "").strip()
    filter_type  = request.args.get("type", "").strip()
    filter_status = request.args.get("status", "").strip()

    if not query and not filter_type and not filter_status:
        return jsonify([])

    sql    = "SELECT * FROM intel_entries WHERE 1=1"
    params = []

    if query:
        sql    += " AND (value LIKE ? OR source_list LIKE ?)"
        params += [f"%{query}%", f"%{query}%"]
    if filter_type:
        sql    += " AND type = ?"
        params.append(filter_type)
    if filter_status:
        sql    += " AND status = ?"
        params.append(filter_status)

    sql += " ORDER BY CASE status WHEN 'approved' THEN 0 WHEN 'pending_review' THEN 1 WHEN 'pending' THEN 2 WHEN 'rejected' THEN 3 ELSE 4 END, first_seen DESC LIMIT 200"

    conn = get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    results = []
    for row in rows:
        r = dict(row)
        r["source_list"] = json.loads(r.get("source_list") or "[]")
        results.append(r)

    return jsonify(results)


# ---------------------------------------------------------------------------
# Manual entry route
# ---------------------------------------------------------------------------

@app.route("/manual", methods=["POST"])
def manual_entry():
    data           = request.get_json()
    indicator_type = data.get("type", "").strip().lower()
    value          = data.get("value", "").strip()
    source_key     = data.get("source_type", "").strip()
    source_label   = data.get("source_label", "").strip()

    if indicator_type not in INDICATOR_TYPES:
        return jsonify({"error": "Invalid indicator type."}), 400
    if not value:
        return jsonify({"error": "Indicator value is required."}), 400
    if source_key not in HUMAN_SOURCES:
        return jsonify({"error": "Invalid source type."}), 400
    if not source_label:
        source_label = HUMAN_SOURCES[source_key]["label"]

    source_info = HUMAN_SOURCES[source_key]

    try:
        normalized = normalize_human_entry(
            value          = value,
            indicator_type = indicator_type,
            source_label   = source_label,
            source_tier    = source_info["tier"],
            base_weight    = source_info["weight"],
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    from src.db.ingest import ingest_entry
    result = ingest_entry(normalized, source_label, source_info["tier"])

    return jsonify({"status": result, "value": normalized["value"], "type": normalized["type"]})


# ---------------------------------------------------------------------------
# Export routes
# ---------------------------------------------------------------------------

@app.route("/export", methods=["POST"])
def export_standard():
    result = generate_export(export_type="standard")
    return jsonify(result)


@app.route("/export/urgent", methods=["POST"])
def export_urgent():
    result = generate_export(export_type="urgent")
    return jsonify(result)


@app.route("/snapshots")
def snapshots():
    return jsonify(list_snapshots())


@app.route("/rollback/<int:snapshot_id>", methods=["POST"])
def rollback(snapshot_id):
    result = rollback_to_snapshot(snapshot_id)
    return jsonify(result)


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Intel Pipeline</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #121212; color: #e0e0e0; font-family: 'Courier New', monospace; font-size: 0.85rem; }
    .section-header { background: #1e1e1e; border-left: 3px solid #444; padding: 6px 12px; margin: 18px 0 10px 0; font-size: 0.75rem; letter-spacing: 0.1em; text-transform: uppercase; color: #888; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; }
    .card-header { background: #222; border-bottom: 1px solid #2a2a2a; font-size: 0.8rem; }
    .table { color: #e0e0e0; font-size: 0.8rem; }
    .table th { color: #888; border-color: #2a2a2a; font-weight: normal; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.08em; }
    .table td { border-color: #2a2a2a; vertical-align: middle; }
    .table tbody tr:hover { background: #1f1f1f; }
    .btn { font-size: 0.78rem; }
    .btn-primary   { background: #1a6b3a; border-color: #1a6b3a; }
    .btn-primary:hover { background: #1e8045; border-color: #1e8045; }
    .btn-warning   { background: #7a5c00; border-color: #7a5c00; color: #ffd; }
    .btn-warning:hover { background: #9a7400; border-color: #9a7400; }
    .btn-danger    { background: #6b1a1a; border-color: #6b1a1a; }
    .btn-danger:hover { background: #8a2020; border-color: #8a2020; }
    .btn-secondary { background: #2a2a2a; border-color: #3a3a3a; }
    .btn-secondary:hover { background: #333; }
    .btn-outline-secondary { border-color: #3a3a3a; color: #aaa; }
    .btn-outline-secondary:hover { background: #2a2a2a; color: #e0e0e0; }
    .badge-pending-review { background: #7a5c00; color: #ffd; }
    .badge-pending        { background: #1a3a5c; color: #acd; }
    .badge-approved       { background: #1a4a2a; color: #8d8; }
    .badge-rejected       { background: #4a1a1a; color: #d88; }
    .badge-expired        { background: #2a2a2a; color: #888; }
    .feed-ok   { background: #1a4a2a; color: #8d8; padding: 2px 8px; border-radius: 3px; font-size: 0.7rem; }
    .feed-fail { background: #4a1a1a; color: #d88; padding: 2px 8px; border-radius: 3px; font-size: 0.7rem; }
    .feed-none { background: #2a2a2a; color: #888; padding: 2px 8px; border-radius: 3px; font-size: 0.7rem; }
    .modal-content { background: #1a1a1a; border: 1px solid #333; color: #e0e0e0; }
    .modal-header { border-bottom: 1px solid #2a2a2a; }
    .modal-footer { border-top: 1px solid #2a2a2a; }
    .form-control, .form-select { background: #111; border: 1px solid #333; color: #e0e0e0; font-size: 0.82rem; }
    .form-control:focus, .form-select:focus { background: #111; color: #e0e0e0; border-color: #555; box-shadow: none; }
    .form-label { color: #888; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .diff-removed { background: #3a0a0a; color: #f88; padding: 2px 6px; border-left: 3px solid #a33; margin: 2px 0; font-size: 0.78rem; }
    .diff-added   { background: #0a3a0a; color: #8f8; padding: 2px 6px; border-left: 3px solid #3a3; margin: 2px 0; font-size: 0.78rem; }
    .diff-label   { color: #666; font-size: 0.7rem; text-transform: uppercase; margin-top: 6px; }
    .note-entry   { background: #111; border-left: 2px solid #333; padding: 4px 8px; margin: 4px 0; font-size: 0.78rem; }
    .note-time    { color: #555; font-size: 0.7rem; }
    .separator    { border-top: 1px dashed #333; margin: 12px 0; }
    .separator-label { color: #555; font-size: 0.7rem; text-align: center; margin: -8px auto 12px; background: #121212; width: fit-content; padding: 0 8px; }
    .tlp-white  { color: #fff; }
    .tlp-green  { color: #4caf50; }
    .tlp-amber  { color: #ff9800; }
    .tlp-red    { color: #f44336; }
    input::placeholder { color: #444; }
    ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #111; } ::-webkit-scrollbar-thumb { background: #333; }
  </style>
</head>
<body>
<div class="container-fluid px-4 py-3" style="max-width:1400px">

  <!-- Header -->
  <div class="d-flex justify-content-between align-items-center mb-2">
    <div>
      <span style="font-size:1.1rem;font-weight:bold;letter-spacing:0.15em;">INTEL PIPELINE</span>
      <span class="ms-3" style="color:#555;font-size:0.75rem;">Night's Watch Home SOC</span>
    </div>
    <div style="color:#555;font-size:0.75rem;" id="clock"></div>
  </div>

  <!-- Feed Health Strip -->
  <div class="section-header">Feed Status</div>
  <div class="d-flex flex-wrap gap-2 mb-3" id="feed-health-strip">
    {% for f in feed_health %}
    <div class="d-flex align-items-center gap-1">
      <span style="color:#888;font-size:0.72rem;">{{ f.feed_name }}</span>
      <span class="{{ 'feed-ok' if f.status == 'success' else 'feed-fail' if f.status == 'failed' else 'feed-none' }}">
        {{ f.status | upper }}
      </span>
    </div>
    {% else %}
    <span style="color:#555;font-size:0.75rem;">No pulls yet.</span>
    {% endfor %}
  </div>

  <!-- Pull Buttons -->
  <div class="section-header">Feed Pulls</div>
  <div class="d-flex flex-wrap gap-2 mb-2">
    <button class="btn btn-primary" onclick="pullAll()">Pull All Feeds</button>
    {% for name in feed_names %}
    <button class="btn btn-outline-secondary btn-sm" onclick="pullOne('{{ name }}')">{{ name }}</button>
    {% endfor %}
  </div>
  <div id="pull-status" style="color:#888;font-size:0.75rem;min-height:1.2rem;margin-bottom:6px;"></div>

  <!-- Export Buttons -->
  <div class="d-flex gap-2 mb-3">
    <button class="btn btn-secondary btn-sm" onclick="generateExport('standard')">Generate Export</button>
    <button class="btn btn-warning btn-sm" onclick="confirmUrgentExport()">Urgent Export</button>
    <button class="btn btn-secondary btn-sm" data-bs-toggle="modal" data-bs-target="#snapshotsModal">Snapshots / Rollback</button>
  </div>
  <div id="export-status" style="color:#888;font-size:0.75rem;min-height:1.2rem;margin-bottom:6px;"></div>

  <!-- Approval Queue -->
  <div class="section-header d-flex justify-content-between">
    <span>Approval Queue</span>
    <span style="font-size:0.72rem;color:#666;">
      <span style="color:#ffd;">{{ pending_review_count }} re-review</span>
      &nbsp;&nbsp;
      <span style="color:#acd;">{{ total }} total</span>
    </span>
  </div>

  <!-- Queue filter and pagination controls -->
  <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
    <span style="color:#666;font-size:0.75rem;">Filter:</span>
    <a href="/?type_filter=&page=1" class="btn btn-sm {{ 'btn-secondary' if not type_filter else 'btn-outline-secondary' }}">All</a>
    {% for t in indicator_types %}
    <a href="/?type_filter={{ t }}&page=1" class="btn btn-sm {{ 'btn-secondary' if type_filter == t else 'btn-outline-secondary' }}">{{ t | upper }}</a>
    {% endfor %}
  </div>

  {% if queue %}
  <div class="table-responsive mb-2">
    <table class="table table-sm table-hover mb-0">
      <thead><tr>
        <th>Status</th><th>Type</th><th>Value</th><th>Description</th><th>Confidence</th>
        <th>Sug. Severity</th><th>Sug. TLP</th><th>Sources</th><th>First Seen</th><th></th>
      </tr></thead>
      <tbody id="queue-tbody">
      {% for e in queue %}
        <tr id="row-{{ e.id }}">
          <td><span class="badge {{ 'badge-pending-review' if e.status == 'pending_review' else 'badge-pending' }}">{{ e.status }}</span></td>
          <td>{{ e.type | upper }}</td>
          <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{{ e.value }}">{{ e.value }}</td>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#aaa;" title="{{ e.description or '' }}">{{ e.description or '—' }}</td>
          <td>{{ "%.0f"|format(e.confidence) }}</td>
          <td>{{ e.suggested_severity }}</td>
          <td class="{{ 'tlp-white' if e.suggested_tlp == 'TLP:WHITE' else 'tlp-green' if e.suggested_tlp == 'TLP:GREEN' else 'tlp-amber' if e.suggested_tlp == 'TLP:AMBER' else 'tlp-red' }}">{{ e.suggested_tlp }}</td>
          <td>{{ e.source_count }}</td>
          <td>{{ e.first_seen[:10] }}</td>
          <td><button class="btn btn-outline-secondary btn-sm" onclick="openEntry({{ e.id }})">Review</button></td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Pagination -->
  {% if total_pages > 1 %}
  <div class="d-flex align-items-center gap-2 mb-3" style="font-size:0.78rem;">
    {% if current_page > 1 %}
    <a href="/?type_filter={{ type_filter }}&page={{ current_page - 1 }}" class="btn btn-outline-secondary btn-sm">Prev</a>
    {% endif %}
    <span style="color:#666;">Page {{ current_page }} of {{ total_pages }}</span>
    {% if current_page < total_pages %}
    <a href="/?type_filter={{ type_filter }}&page={{ current_page + 1 }}" class="btn btn-outline-secondary btn-sm">Next</a>
    {% endif %}
  </div>
  {% endif %}

  {% else %}
  <div style="color:#555;font-size:0.8rem;margin-bottom:12px;">Queue is empty{% if type_filter %} for type {{ type_filter | upper }}{% endif %}.</div>
  {% endif %}

  <!-- Search -->
  <div class="section-header">Search</div>
  <div class="row g-2 mb-2">
    <div class="col-md-5">
      <input type="text" class="form-control form-control-sm" id="search-input" placeholder="Value or source..." onkeydown="if(event.key==='Enter') doSearch()">
    </div>
    <div class="col-md-2">
      <select class="form-select form-select-sm" id="search-type">
        <option value="">All types</option>
        {% for t in indicator_types %}<option value="{{ t }}">{{ t | upper }}</option>{% endfor %}
      </select>
    </div>
    <div class="col-md-2">
      <select class="form-select form-select-sm" id="search-status">
        <option value="">All statuses</option>
        <option value="pending">Pending</option>
        <option value="pending_review">Pending Review</option>
        <option value="approved">Approved</option>
        <option value="rejected">Rejected</option>
        <option value="expired">Expired</option>
      </select>
    </div>
    <div class="col-md-1">
      <button class="btn btn-secondary btn-sm w-100" onclick="doSearch()">Search</button>
    </div>
  </div>
  <div id="search-results"></div>

  <!-- Manual Entry -->
  <div class="section-header">Manual Entry</div>
  <div class="card mb-4">
    <div class="card-body">
      <div class="row g-2">
        <div class="col-md-2">
          <label class="form-label">Type</label>
          <select class="form-select form-select-sm" id="manual-type" onchange="updateManualFields()">
            <option value="">Select type</option>
            {% for t in indicator_types %}<option value="{{ t }}">{{ t | upper }}</option>{% endfor %}
          </select>
        </div>
        <div id="manual-fields" class="col-md-5"></div>
        <div class="col-md-2">
          <label class="form-label">Source Type</label>
          <select class="form-select form-select-sm" id="manual-source-type">
            <option value="">Select source</option>
            {% for k, v in human_sources.items() %}<option value="{{ k }}">{{ v.label }} ({{ v.weight }})</option>{% endfor %}
          </select>
        </div>
        <div class="col-md-2">
          <label class="form-label">Source Label</label>
          <input type="text" class="form-control form-control-sm" id="manual-source-label" placeholder="e.g. SANS email">
        </div>
        <div class="col-md-1 d-flex align-items-end">
          <button class="btn btn-primary btn-sm w-100" onclick="submitManual()">Submit</button>
        </div>
      </div>
      <div id="manual-status" style="color:#888;font-size:0.75rem;margin-top:6px;min-height:1rem;"></div>
    </div>
  </div>

</div><!-- /container -->

<!-- Entry Review Modal -->
<div class="modal fade" id="entryModal" tabindex="-1">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header py-2">
        <span class="modal-title" id="modal-title" style="font-size:0.9rem;">Entry Review</span>
        <button type="button" class="btn-close btn-close-white btn-sm" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body" id="modal-body" style="font-size:0.82rem;"></div>
      <div class="modal-footer py-2 d-flex justify-content-between">
        <div class="d-flex gap-2">
          <select class="form-select form-select-sm" id="modal-severity" style="width:120px;">
            {% for s in severity_values %}<option value="{{ s }}">{{ s }}</option>{% endfor %}
          </select>
          <select class="form-select form-select-sm" id="modal-tlp" style="width:130px;">
            {% for t in tlp_values %}<option value="{{ t }}">{{ t }}</option>{% endfor %}
          </select>
          <select class="form-select form-select-sm" id="modal-action" style="width:100px;">
            {% for a in engine_actions %}<option value="{{ a }}">{{ a }}</option>{% endfor %}
          </select>
        </div>
        <div class="d-flex gap-2">
          <button class="btn btn-danger btn-sm" id="modal-reject-btn" onclick="rejectEntry()">Reject</button>
          <button class="btn btn-primary btn-sm" id="modal-approve-btn" onclick="approveEntry()">Approve</button>
          <button class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cancel</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Snapshots Modal -->
<div class="modal fade" id="snapshotsModal" tabindex="-1">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header py-2">
        <span class="modal-title" style="font-size:0.9rem;">Export Snapshots</span>
        <button type="button" class="btn-close btn-close-white btn-sm" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body" id="snapshots-body" style="font-size:0.82rem;"></div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
// --- Current entry being reviewed ---
let currentEntryId = null;

// --- Clock ---
function updateClock() {
  document.getElementById('clock').textContent = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// --- Feed pulls ---
async function pullAll() {
  document.getElementById('pull-status').textContent = 'Pulling all feeds...';
  try {
    const res = await fetch('/pull/all', { method: 'POST' });
    const data = await res.json();
    const summary = data.map(r =>
      `${r.feed}: ${r.status} (${r.summary.inserted || 0} new)`
    ).join(' | ');
    document.getElementById('pull-status').textContent = summary;
    refreshFeedHealth();
    location.reload();
  } catch(e) {
    document.getElementById('pull-status').textContent = 'Pull failed: ' + e;
  }
}

async function pullOne(feedName) {
  document.getElementById('pull-status').textContent = `Pulling ${feedName}...`;
  try {
    const res = await fetch(`/pull/${encodeURIComponent(feedName)}`, { method: 'POST' });
    const data = await res.json();
    document.getElementById('pull-status').textContent =
      `${data.feed}: ${data.status} — ${data.summary.inserted || 0} new, ${data.error || 'no errors'}`;
    refreshFeedHealth();
    location.reload();
  } catch(e) {
    document.getElementById('pull-status').textContent = 'Pull failed: ' + e;
  }
}

async function refreshFeedHealth() {
  try {
    const res  = await fetch('/feed_health');
    const data = await res.json();
    const strip = document.getElementById('feed-health-strip');
    strip.innerHTML = data.map(f => `
      <div class="d-flex align-items-center gap-1">
        <span style="color:#888;font-size:0.72rem;">${f.feed_name}</span>
        <span class="${f.status === 'success' ? 'feed-ok' : f.status === 'failed' ? 'feed-fail' : 'feed-none'}">
          ${f.status.toUpperCase()}
        </span>
      </div>
    `).join('');
  } catch(e) {}
}

// --- Exports ---
async function generateExport(type) {
  document.getElementById('export-status').textContent = 'Generating export...';
  try {
    const res  = await fetch(`/export${type === 'urgent' ? '/urgent' : ''}`, { method: 'POST' });
    const data = await res.json();
    document.getElementById('export-status').textContent =
      `Export: ${data.filename} | ${data.entry_count} entries | ${data.tlp}`;
  } catch(e) {
    document.getElementById('export-status').textContent = 'Export failed: ' + e;
  }
}

function confirmUrgentExport() {
  if (confirm('Generate an URGENT export now? This bypasses the normal daily cycle.')) {
    generateExport('urgent');
  }
}

async function loadSnapshots() {
  const res  = await fetch('/snapshots');
  const data = await res.json();
  const body = document.getElementById('snapshots-body');
  if (!data.length) { body.innerHTML = '<p style="color:#555">No snapshots.</p>'; return; }
  body.innerHTML = `
    <table class="table table-sm">
      <thead><tr><th>ID</th><th>Exported At</th><th>Type</th><th>Entries</th><th>TLP</th><th>SHA256</th><th></th></tr></thead>
      <tbody>
        ${data.map(s => `
          <tr>
            <td>${s.id}</td>
            <td>${s.exported_at.slice(0,19)}</td>
            <td>${s.export_type}</td>
            <td>${s.entry_count}</td>
            <td>${s.tlp}</td>
            <td style="font-size:0.7rem;">${s.sha256.slice(0,16)}...</td>
            <td><button class="btn btn-warning btn-sm" onclick="doRollback(${s.id})">Rollback</button></td>
          </tr>
        `).join('')}
      </tbody>
    </table>`;
}

document.getElementById('snapshotsModal').addEventListener('show.bs.modal', loadSnapshots);

async function doRollback(snapshotId) {
  if (!confirm(`Roll back to snapshot ${snapshotId}? A new export will be created from this snapshot.`)) return;
  const res  = await fetch(`/rollback/${snapshotId}`, { method: 'POST' });
  const data = await res.json();
  if (data.error) { alert('Rollback failed: ' + data.error); return; }
  alert(`Rollback complete: ${data.filename}`);
  loadSnapshots();
}

// --- Entry review modal ---
async function openEntry(id) {
  currentEntryId = id;
  const res  = await fetch(`/entry/${id}`);
  const data = await res.json();

  document.getElementById('modal-title').textContent =
    `Review — ${data.type.toUpperCase()}: ${data.value}`;

  // Pre-fill dropdowns with suggestions
  document.getElementById('modal-severity').value = data.suggested_severity || 'low';
  document.getElementById('modal-tlp').value      = data.suggested_tlp || 'TLP:GREEN';
  document.getElementById('modal-action').value   = data.engine_action || 'Alert';

  let html = '';

  // Entry details
  html += `<div class="row g-2 mb-3">
    <div class="col-6">
      <div style="color:#666;font-size:0.7rem;">VALUE</div>
      <div style="word-break:break-all;">${data.value}</div>
    </div>
    <div class="col-3">
      <div style="color:#666;font-size:0.7rem;">CONFIDENCE</div>
      <div>${data.confidence.toFixed(1)}</div>
    </div>
    <div class="col-3">
      <div style="color:#666;font-size:0.7rem;">EVIDENCE CLASS</div>
      <div>${data.evidence_class}</div>
    </div>
    ${data.description ? `
    <div class="col-12">
      <div style="color:#666;font-size:0.7rem;">DESCRIPTION</div>
      <div style="color:#bbb;">${data.description}</div>
    </div>` : ''}
    <div class="col-6">
      <div style="color:#666;font-size:0.7rem;">SOURCES</div>
      <div>${Array.isArray(data.source_list) ? data.source_list.join(', ') : data.source_list}</div>
    </div>
    <div class="col-3">
      <div style="color:#666;font-size:0.7rem;">LANE</div>
      <div>${data.lane}</div>
    </div>
    <div class="col-3">
      <div style="color:#666;font-size:0.7rem;">EXPIRES</div>
      <div>${data.expires_at ? data.expires_at.slice(0,10) : 'Never'}</div>
    </div>
  </div>`;

  // Diff for pending_review
  if (data.status === 'pending_review') {
    html += `<div class="diff-label">Changes requiring re-review</div>`;
    html += `<div class="diff-removed">suggested_severity: ${data.suggested_severity}</div>`;
    html += `<div class="diff-added">confidence: ${data.confidence.toFixed(1)} (updated by feed)</div>`;
  }

  // Notes history or fallback to approval timestamp
  html += `<div class="separator"></div>`;
  html += `<div style="color:#666;font-size:0.7rem;margin-bottom:4px;">ANALYST NOTES</div>`;

  if (data.notes && data.notes.length > 0) {
    html += data.notes.map(n => `
      <div class="note-entry">
        <div class="note-time">${n.created_at.slice(0,19)} UTC${n.created_by ? ' — ' + n.created_by : ''}</div>
        <div>${n.note}</div>
      </div>`).join('');
  } else if (data.approved_at) {
    html += `<div class="note-entry" style="color:#555;">No notes. Approved at ${data.approved_at.slice(0,19)} UTC.</div>`;
  } else {
    html += `<div style="color:#555;font-size:0.78rem;">No notes yet.</div>`;
  }

  // Note input
  html += `<div class="separator"></div>`;
  html += `<label class="form-label">Add Note</label>`;
  html += `<textarea class="form-control form-control-sm" id="modal-note" rows="2" placeholder="Optional note..."></textarea>`;
  html += `<div id="modal-error" style="color:#f66;font-size:0.75rem;margin-top:4px;min-height:1rem;"></div>`;

  document.getElementById('modal-body').innerHTML = html;

  const modal = new bootstrap.Modal(document.getElementById('entryModal'));
  modal.show();
}

async function approveEntry() {
  const note = document.getElementById('modal-note').value.trim();
  const res  = await fetch(`/approve/${currentEntryId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approved_severity: document.getElementById('modal-severity').value,
      approved_tlp:      document.getElementById('modal-tlp').value,
      engine_action:     document.getElementById('modal-action').value,
      note:              note,
    })
  });
  const data = await res.json();
  if (data.error) {
    document.getElementById('modal-error').textContent = data.error;
    return;
  }
  bootstrap.Modal.getInstance(document.getElementById('entryModal')).hide();
  document.getElementById(`row-${currentEntryId}`)?.remove();
}

async function rejectEntry() {
  const note = document.getElementById('modal-note').value.trim();
  if (!note) {
    document.getElementById('modal-error').textContent = 'A note is required to reject an entry.';
    return;
  }
  const res  = await fetch(`/reject/${currentEntryId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note })
  });
  const data = await res.json();
  if (data.error) {
    document.getElementById('modal-error').textContent = data.error;
    return;
  }
  bootstrap.Modal.getInstance(document.getElementById('entryModal')).hide();
  document.getElementById(`row-${currentEntryId}`)?.remove();
}

// --- Search ---
async function doSearch() {
  const q      = document.getElementById('search-input').value.trim();
  const type   = document.getElementById('search-type').value;
  const status = document.getElementById('search-status').value;
  if (!q && !type && !status) { return; }

  const params = new URLSearchParams();
  if (q)      params.append('q', q);
  if (type)   params.append('type', type);
  if (status) params.append('status', status);

  const res     = await fetch('/search?' + params.toString());
  const results = await res.json();

  const active   = results.filter(r => !['rejected','expired'].includes(r.status));
  const inactive = results.filter(r =>  ['rejected','expired'].includes(r.status));

  function renderRows(entries) {
    return entries.map(e => `
      <tr>
        <td><span class="badge badge-${e.status.replace('_','-')}">${e.status}</span></td>
        <td>${e.type.toUpperCase()}</td>
        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${e.value}">${e.value}</td>
        <td>${e.confidence.toFixed(0)}</td>
        <td>${e.approved_severity || e.suggested_severity}</td>
        <td>${e.approved_tlp || e.suggested_tlp}</td>
        <td>${e.source_count}</td>
        <td>${e.first_seen.slice(0,10)}</td>
        <td>${['pending','pending_review'].includes(e.status) ? `<button class="btn btn-outline-secondary btn-sm" onclick="openEntry(${e.id})">Review</button>` : ''}</td>
      </tr>`).join('');
  }

  let html = `<div class="table-responsive"><table class="table table-sm table-hover">
    <thead><tr><th>Status</th><th>Type</th><th>Value</th><th>Confidence</th><th>Severity</th><th>TLP</th><th>Sources</th><th>First Seen</th><th></th></tr></thead>
    <tbody>${renderRows(active)}`;

  if (inactive.length > 0) {
    html += `<tr><td colspan="9" class="p-0">
      <div class="separator"></div>
      <div class="separator-label">Rejected / Expired</div>
    </td></tr>`;
    html += renderRows(inactive);
  }

  html += `</tbody></table></div>`;
  html += `<div style="color:#555;font-size:0.72rem;">${results.length} result(s)</div>`;
  document.getElementById('search-results').innerHTML = html;
}

// --- Manual entry ---
function updateManualFields() {
  const type = document.getElementById('manual-type').value;
  const container = document.getElementById('manual-fields');
  if (!type) { container.innerHTML = ''; return; }

  let html = '';
  if (type === 'hash') {
    html = `
      <label class="form-label">Hash Type</label>
      <select class="form-select form-select-sm mb-1" id="manual-hash-type">
        <option value="md5">MD5</option>
        <option value="sha1">SHA1</option>
        <option value="sha256" selected>SHA256</option>
      </select>
      <label class="form-label">Hash Value</label>
      <input type="text" class="form-control form-control-sm" id="manual-value" placeholder="Hash value...">`;
  } else if (type === 'cve') {
    html = `<label class="form-label">CVE ID</label>
      <input type="text" class="form-control form-control-sm" id="manual-value" placeholder="CVE-2026-XXXX">`;
  } else if (type === 'asn') {
    html = `<label class="form-label">ASN Number</label>
      <input type="text" class="form-control form-control-sm" id="manual-value" placeholder="13335 or AS13335">`;
  } else if (type === 'ttp') {
    html = `<label class="form-label">ATT&CK Technique ID</label>
      <input type="text" class="form-control form-control-sm" id="manual-value" placeholder="T1059.001">`;
  } else {
    html = `<label class="form-label">${type.toUpperCase()}</label>
      <input type="text" class="form-control form-control-sm" id="manual-value" placeholder="${type}...">`;
  }
  container.innerHTML = html;
}

async function submitManual() {
  const type        = document.getElementById('manual-type').value;
  const value       = document.getElementById('manual-value')?.value.trim();
  const sourceType  = document.getElementById('manual-source-type').value;
  const sourceLabel = document.getElementById('manual-source-label').value.trim();
  const statusEl    = document.getElementById('manual-status');

  if (!type || !value || !sourceType) {
    statusEl.textContent = 'Type, value, and source type are required.';
    statusEl.style.color = '#f66';
    return;
  }

  const res  = await fetch('/manual', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, value, source_type: sourceType, source_label: sourceLabel })
  });
  const data = await res.json();

  if (data.error) {
    statusEl.textContent = data.error;
    statusEl.style.color = '#f66';
  } else {
    statusEl.textContent = `Submitted: ${data.type.toUpperCase()} ${data.value} (${data.status})`;
    statusEl.style.color = '#8d8';
    document.getElementById('manual-value').value = '';
  }
}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    seed_feed_config()
    run_decay()
    app.run(host="127.0.0.1", port=6001, debug=False)
