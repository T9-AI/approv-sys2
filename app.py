# app.py
# Decision Request System - Full Phase 1 Backend
# - Flask + SQLite (no ORM)
# - Auth (Admin/Manager/User)
# - Workflow engine (Approve / Reject / Need Review) with forward/backward routing
# - Per-request manager action type override (Viewer or Signer) + Admin default workflow template
# - Audit trail (full event log)
# - Email notifications (SMTP optional)
# - PDF exports:
#     1) Decision Request Form PDF export
#     2) Audit Certificate PDF export ("Certificate of Fulfilment" style)
#
# NOTE:
#   - This file auto-creates minimal placeholder templates/static if missing,
#     so the app runs immediately. Replace them with the exact 1:1 templates
#     you want in message (2/3) and (3/3).
#
# Python 3.10+ recommended.

from __future__ import annotations

import base64
import datetime as dt
import io
import json
import os
import re
import smtplib
import sqlite3
import textwrap
import traceback
import uuid
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# reportlab for PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

#####################################################################################
# Config
#####################################################################################

APP_NAME = "Decision Request System"

BASE_DIR = Path(__file__).resolve().parent
# Database path:
# - If APP_DB_PATH env var is set, use it (must still point to app.db unless overridden intentionally).
# - Otherwise, always use app.db in the repo root to avoid accidental creation of a secondary DB.
_env_db = (os.getenv("APP_DB_PATH") or "").strip()
if _env_db:
    DB_PATH = Path(_env_db)
else:
    DB_PATH = BASE_DIR / "app.db"
UPLOAD_DIR = Path(os.getenv("APP_UPLOAD_DIR", str(BASE_DIR / "uploads")))
ASSETS_DIR = Path(os.getenv("APP_ASSETS_DIR", str(BASE_DIR / "assets")))

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

# Optional: put your template PDF background here later (exact layout overlay)
# e.g. assets/form_template.pdf
FORM_TEMPLATE_PDF = Path(os.getenv("APP_FORM_TEMPLATE_PDF", str(ASSETS_DIR / "form_template.pdf")))

# Email (optional). If not configured, emails are logged to console.
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@example.com")
SMTP_TLS = os.getenv("SMTP_TLS", "1") == "1"

# Security
SECRET_KEY = os.getenv("APP_SECRET_KEY", "CHANGE_ME__" + uuid.uuid4().hex)

# Uploads
ALLOWED_UPLOAD_EXTENSIONS = {"pdf", "xlsx", "xls", "doc", "docx", "png", "jpg", "jpeg"}

# Roles
ROLE_ADMIN = "admin"
ROLE_MANAGER = "manager"
ROLE_USER = "user"

# Decisions / step states
DECISION_PENDING = "pending"
DECISION_APPROVED = "approved"
DECISION_REJECTED = "rejected"
DECISION_NEED_REVIEW = "need_review"

DECISIONS = {DECISION_PENDING, DECISION_APPROVED, DECISION_REJECTED, DECISION_NEED_REVIEW}

# Request status (high-level)
REQ_DRAFT = "draft"
REQ_IN_REVIEW = "in_review"
REQ_RETURNED = "returned_to_requester"
REQ_APPROVED = "approved"
REQ_ARCHIVED = "archived"

REQ_STATUSES = {REQ_DRAFT, REQ_IN_REVIEW, REQ_RETURNED, REQ_APPROVED, REQ_ARCHIVED}


#####################################################################################
# App
#####################################################################################

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.config.update(
    SECRET_KEY=SECRET_KEY,
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # 25MB
    TEMPLATES_AUTO_RELOAD=True,
)


#####################################################################################
# Utilities
#####################################################################################

def now_utc_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def today_iso() -> str:
    return dt.date.today().isoformat()


def safe_json_loads(s: str | None, default: Any) -> Any:
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def normalize_data_url_png(data_url: str) -> str:
    """
    Accepts:
      - data:image/png;base64,...
      - raw base64
    Returns normalized data URL.
    """
    if not data_url:
        return ""
    if data_url.startswith("data:image"):
        return data_url
    # assume base64 png
    return "data:image/png;base64," + data_url.strip()


def decode_data_url_to_bytes(data_url: str) -> bytes:
    data_url = (data_url or "").strip()
    if not data_url:
        return b""
    if data_url.startswith("data:image"):
        m = re.match(r"data:image/\w+;base64,(.*)", data_url, re.DOTALL)
        if not m:
            return b""
        b64 = m.group(1)
        return base64.b64decode(b64)
    return base64.b64decode(data_url)



#####################################################################################
# Template / Form compatibility helpers
#####################################################################################

def template_exists(name: str) -> bool:
    """Return True if a template file exists in ./templates."""
    try:
        return (BASE_DIR / "templates" / name).exists()
    except Exception:
        return False


def looks_like_final_request_form(form) -> bool:
    """
    Detect whether POST data is the *full* request form (not the pre-form/setup mask).
    This keeps us compatible with templates that do a 2-step flow:
      1) setup selections (project/unit/type)
      2) full request form with many fields
    """
    if not form:
        return False
    # Explicit hints from template
    stage = (form.get("stage") or form.get("step") or "").strip().lower()
    if stage in ("setup", "prefill", "mask"):
        return False
    if stage in ("form", "create", "final"):
        return True

    keys = set(form.keys())
    # JSON blocks or known full-form keys
    if {"header_json", "mid_json", "meta_json"} & keys:
        return True

    # Any section-based inputs commonly used in your PDF-like form
    for k in keys:
        lk = k.lower()
        if lk.startswith("sec") or lk.startswith("section_"):
            return True
        if lk in ("subject", "reason_for_decision", "internal_notes", "internal_comments", "others_text"):
            return True
        if lk.startswith("decision_") or lk.startswith("comment_") or lk.startswith("signature_data_"):
            return True
    return False


def extract_setup_values(mapping: dict) -> Dict[str, str]:
    """Extract setup-mask fields (project/unit/request_type) from any mapping (args/form)."""
    project = first_nonempty(
        mapping.get("project"),
        mapping.get("project_name"),
        mapping.get("project_code"),
    )
    unit_no = first_nonempty(
        mapping.get("unit_no"),
        mapping.get("unit"),
        mapping.get("unit_number"),
        mapping.get("unit_id"),
    )
    req_type = first_nonempty(
        mapping.get("request_type"),
        mapping.get("req_type"),
        mapping.get("request_kind"),
        mapping.get("type"),
    ) or ""

    setup = {
        "project": (project or "").strip(),
        "unit_no": (unit_no or "").strip(),
        "request_type": (req_type or "").strip(),
    }
    # drop empties
    return {k: v for k, v in setup.items() if v}


def merge_setup_into_session(new_setup: Dict[str, str]) -> Dict[str, str]:
    """Merge any provided setup values into session['request_setup'] and return merged dict."""
    cur = session.get("request_setup") or {}
    if not isinstance(cur, dict):
        cur = {}
    merged = {**cur, **{k: v for k, v in (new_setup or {}).items() if v}}
    if merged:
        session["request_setup"] = merged
    else:
        session.pop("request_setup", None)
    return merged


def build_status_text(req_row: sqlite3.Row | Dict[str, Any]) -> str:
    try:
        status = req_row["status"]
        current_step = int(req_row.get("current_step_order") if isinstance(req_row, dict) else req_row["current_step_order"])
        last_dec = (req_row.get("last_decision") if isinstance(req_row, dict) else req_row["last_decision"]) or ""
        last_step = int(
            req_row.get("last_decision_step") if isinstance(req_row, dict) else req_row["last_decision_step"] or 0
        )
        return_reason = (req_row.get("return_reason") if isinstance(req_row, dict) else req_row["return_reason"]) or ""
        return_from_step = int(
            req_row.get("return_from_step") if isinstance(req_row, dict) else req_row["return_from_step"] or 0
        )
        cycle_no = int(req_row.get("cycle_no") if isinstance(req_row, dict) else req_row["cycle_no"] or 1)
        steps = get_request_steps(int(req_row.get("id") if isinstance(req_row, dict) else req_row["id"]), cycle_no)
    except Exception:
        return ""

    def title(dec: str) -> str:
        if dec == DECISION_APPROVED:
            return "Approved"
        if dec == DECISION_REJECTED:
            return "Rejected"
        if dec == DECISION_NEED_REVIEW:
            return "Need Review"
        return "Pending"

    def manager_name(step: int) -> str:
        for s in steps:
            if int(s["step_order"]) == int(step):
                return s.get("manager_name") or ""
        return ""

    if status == REQ_APPROVED:
        return "Completed"
    if status == REQ_DRAFT:
        return "Draft"
    if status == REQ_IN_REVIEW:
        lbl = f"Pending {current_step if current_step else 1}"
        nm = manager_name(current_step)
        return f"{lbl} - {nm}" if nm else lbl
    if status == REQ_RETURNED:
        step = return_from_step or last_step or 1
        rr = return_reason or last_dec or DECISION_NEED_REVIEW
        lbl = f"{title(rr)} {step}"
        nm = manager_name(step)
        return f"{lbl} - {nm}" if nm else lbl
    if last_dec:
        lbl = f"{title(last_dec)} {last_step or current_step or 1}"
        nm = manager_name(last_step)
        return f"{lbl} - {nm}" if nm else lbl
    return status


def build_req_obj(req_row: Any, include_steps: bool = True) -> Dict[str, Any]:
    """
    Build a template-friendly request object:
      - keeps original columns
      - adds header/mid/meta dicts
      - flattens header+mid+meta keys onto the top level for Jinja convenience
      - attaches steps and attachments
    This avoids "data missing" issues between form/view/edit/dashboard/report templates.
    """
    base = dict(req_row) if not isinstance(req_row, dict) else dict(req_row)

    header = safe_json_loads(base.get("header_json"), {}) if "header_json" in base else safe_json_loads(base.get("header"), {})
    mid = safe_json_loads(base.get("mid_json"), {}) if "mid_json" in base else safe_json_loads(base.get("mid"), {})
    meta = safe_json_loads(base.get("meta_json"), {}) if "meta_json" in base else safe_json_loads(base.get("meta"), {})
    attachments = safe_json_loads(base.get("attachments_json"), []) if "attachments_json" in base else safe_json_loads(base.get("attachments"), [])

    if not isinstance(header, dict):
        header = {}
    if not isinstance(mid, dict):
        mid = {}
    if not isinstance(meta, dict):
        meta = {}

    base["header"] = header
    base["mid"] = mid
    base["meta"] = meta
    base["attachments"] = attachments

    # Labels
    try:
        base["status_label"] = compute_status_label(
            req_row if isinstance(req_row, sqlite3.Row) else db_query_one("SELECT * FROM requests WHERE id=?", (int(base.get("id", 0)),))
        )
    except Exception:
        base["status_label"] = base.get("status", "")
    try:
        base["last_decision_label"] = compute_last_decision_label(
            req_row if isinstance(req_row, sqlite3.Row) else db_query_one("SELECT * FROM requests WHERE id=?", (int(base.get("id", 0)),))
        )
    except Exception:
        base["last_decision_label"] = ""
    try:
        base["status_text"] = build_status_text(req_row)
    except Exception:
        base["status_text"] = base.get("status_label") or base.get("status", "")

    # Flatten keys (do not overwrite existing columns)
    for src in (header, mid, meta):
        for k, v in src.items():
            if k not in base:
                base[k] = v

    # Steps
    if include_steps and base.get("id"):
        try:
            base["steps"] = [dict(x) for x in get_request_steps(int(base["id"]), int(base.get("cycle_no") or 1))]
        except Exception:
            base["steps"] = []

    return base
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_UPLOAD_EXTENSIONS


def ensure_scaffold_files() -> None:
    """
    Create minimal templates/static so app runs immediately.
    You will replace them with exact 1:1 PDF-matching files later.
    """
    (BASE_DIR / "templates").mkdir(exist_ok=True)
    (BASE_DIR / "static").mkdir(exist_ok=True)

    placeholders: Dict[str, str] = {
        "templates/login.html": """<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
<body style="font-family:Arial;padding:20px;">
<h2>Login</h2>
{% with messages = get_flashed_messages() %}
  {% if messages %}<div style="color:red;">{{ messages[0] }}</div>{% endif %}
{% endwith %}
<form method="post">
  <label>Username</label><br><input name="username"><br><br>
  <label>Password</label><br><input name="password" type="password"><br><br>
  <button type="submit">Login</button>
</form>
</body></html>""",
        "templates/request_form.html": """<!doctype html><html><head><meta charset="utf-8"><title>Request Form</title></head>
<body style="font-family:Arial;padding:20px;">
<h2>Decision Request Form (Placeholder)</h2>
<p>This is a placeholder. Replace with the 1:1 PDF layout.</p>
<p>User: {{ current_user.full_name }} ({{ current_user.role }})</p>

{% if mode == 'create' %}
<form method="post" action="{{ url_for('request_create') }}" enctype="multipart/form-data">
  <label>Request Type</label><br><input name="request_type" value="Decision Request"><br><br>

  <h3>Header Fields (JSON placeholder)</h3>
  <textarea name="header_json" rows="8" cols="90">{}</textarea><br><br>

  <h3>Mid Fields (JSON placeholder)</h3>
  <textarea name="mid_json" rows="10" cols="90">{}</textarea><br><br>

  <h3>Workflow override (viewer/signer per manager)</h3>
  <p>Leave empty to use admin defaults.</p>
  <textarea name="workflow_overrides_json" rows="6" cols="90">[]</textarea><br><br>

  <label>Attachment (optional)</label><br><input type="file" name="attachment"><br><br>

  <button type="submit">Save Draft</button>
</form>
{% else %}
  <pre>{{ request_obj | tojson(indent=2) }}</pre>

  {% if can_submit %}
    <form method="post" action="{{ url_for('request_submit', request_id=request_obj.id) }}">
      <button type="submit">Submit for Approval</button>
    </form>
  {% endif %}

  {% if can_decide %}
    <hr>
    <h3>Manager Decision</h3>
    <form method="post" action="{{ url_for('request_decide', request_id=request_obj.id) }}">
      <label>Decision</label>
      <select name="decision">
        <option value="approved">Approved</option>
        <option value="need_review">Need Review</option>
        <option value="rejected">Rejected</option>
      </select><br><br>
      <label>Notes</label><br>
      <textarea name="notes" rows="4" cols="90"></textarea><br><br>

      {% if require_signature %}
      <label>Signature (data URL)</label><br>
      <textarea name="signature_data_url" rows="4" cols="90"></textarea><br><br>
      <label>Save as default signature?</label> <input type="checkbox" name="save_default" value="1"><br><br>
      {% endif %}

      <button type="submit">Submit Decision</button>
    </form>
  {% endif %}

{% endif %}
</body></html>""",
        "templates/request_view.html": """<!doctype html><html><head><meta charset="utf-8"><title>Request View</title></head>
<body style="font-family:Arial;padding:20px;">
<h2>Request View (Placeholder)</h2>
<p><a href="{{ url_for('inbox') }}">Inbox</a> | <a href="{{ url_for('report') }}">Report</a> | <a href="{{ url_for('logout') }}">Logout</a></p>
<pre>{{ request_obj | tojson(indent=2) }}</pre>
</body></html>""",
        "templates/report.html": """<!doctype html><html><head><meta charset="utf-8"><title>Report</title></head>
<body style="font-family:Arial;padding:20px;">
<h2>Report (Placeholder)</h2>
<form method="get">
  <input name="q" placeholder="search..." value="{{ request.args.get('q','') }}">
  <select name="status">
    <option value="">All</option>
    {% for s in statuses %}
      <option value="{{ s }}" {% if request.args.get('status')==s %}selected{% endif %}>{{ s }}</option>
    {% endfor %}
  </select>
  <button type="submit">Filter</button>
</form>
<table border="1" cellpadding="6" cellspacing="0">
  <tr><th>No</th><th>Request No</th><th>Type</th><th>Requester</th><th>Status Label</th><th>Updated</th><th>Open</th></tr>
  {% for r in rows %}
    <tr>
      <td>{{ loop.index }}</td>
      <td>{{ r['request_no'] }}</td>
      <td>{{ r['request_type'] }}</td>
      <td>{{ r['requester_name'] }}</td>
      <td>{{ r['status_label'] }}</td>
      <td>{{ r['updated_at'] }}</td>
      <td><a href="{{ url_for('request_detail', request_id=r['id']) }}">Open</a></td>
    </tr>
  {% endfor %}
</table>
</body></html>""",
        "templates/admin.html": """<!doctype html><html><head><meta charset="utf-8"><title>Admin</title></head>
<body style="font-family:Arial;padding:20px;">
<h2>Admin Dashboard (Placeholder)</h2>
<p><a href="{{ url_for('logout') }}">Logout</a></p>

<h3>Create User/Manager</h3>
<form method="post" action="{{ url_for('admin_create_user') }}">
  <label>Role</label>
  <select name="role">
    <option value="user">user</option>
    <option value="manager">manager</option>
    <option value="admin">admin</option>
  </select><br><br>
  <label>Full Name</label><br><input name="full_name"><br><br>
  <label>Username</label><br><input name="username"><br><br>
  <label>Email</label><br><input name="email"><br><br>
  <label>Password</label><br><input name="password" type="password"><br><br>
  <button type="submit">Create</button>
</form>

<hr>
<h3>Workflow Template Steps</h3>
<p>Define managers in order. Each step has default action_type (viewer/signer).</p>
<form method="post" action="{{ url_for('admin_set_workflow') }}">
  <textarea name="workflow_json" rows="10" cols="90">{{ workflow_json }}</textarea><br><br>
  <button type="submit">Save Workflow</button>
</form>

<hr>
<h3>Audit Log (latest 50)</h3>
<table border="1" cellpadding="6" cellspacing="0">
  <tr><th>Time</th><th>Actor</th><th>Action</th><th>Request</th><th>Step</th><th>Details</th></tr>
  {% for a in audits %}
    <tr>
      <td>{{ a['created_at'] }}</td>
      <td>{{ a['actor_name'] }} ({{ a['actor_role'] }})</td>
      <td>{{ a['action'] }}</td>
      <td>{{ a['request_id'] or '' }}</td>
      <td>{{ a['step_order'] or '' }}</td>
      <td style="max-width:420px;white-space:pre-wrap;">{{ a['details'] }}</td>
    </tr>
  {% endfor %}
</table>

</body></html>""",
        "static/app.css": "/* placeholder - replace in message (3/3) */\nbody{font-family:Arial;}\n",
        "static/app.js": "// placeholder - replace in message (3/3)\n",
    }

    for rel_path, content in placeholders.items():
        p = BASE_DIR / rel_path
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")


#####################################################################################
# DB
#####################################################################################

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc: Optional[BaseException] = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    """
    Creates all tables if not exist.
    """
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON;")

    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT DEFAULT '',
        role TEXT NOT NULL CHECK(role IN ('admin','manager','user')),
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS manager_profiles (
    manager_id INTEGER PRIMARY KEY,
    title TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
);

    CREATE TABLE IF NOT EXISTS workflow_template_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        step_order INTEGER NOT NULL,
        manager_id INTEGER NOT NULL,
        action_type TEXT NOT NULL CHECK(action_type IN ('viewer','signer')),
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        UNIQUE(step_order),
        FOREIGN KEY(manager_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_no TEXT UNIQUE NOT NULL,
        request_type TEXT NOT NULL,
        created_by_user_id INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('draft','in_review','returned_to_requester','approved','archived')),
        cycle_no INTEGER NOT NULL DEFAULT 1,

        current_step_order INTEGER NOT NULL DEFAULT 0,  -- 0 means requester
        last_decision TEXT DEFAULT '',
        last_decision_step INTEGER DEFAULT 0,
        last_decision_by INTEGER DEFAULT 0,

        return_reason TEXT DEFAULT '',                 -- 'rejected' or 'need_review'
        return_from_step INTEGER DEFAULT 0,

        header_json TEXT NOT NULL DEFAULT '{}',
        mid_json TEXT NOT NULL DEFAULT '{}',
        meta_json TEXT NOT NULL DEFAULT '{}',          -- optional: subject, priority, due_date, etc.
        attachments_json TEXT NOT NULL DEFAULT '[]',   -- list of uploaded files metadata
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(created_by_user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS request_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        cycle_no INTEGER NOT NULL,
        step_order INTEGER NOT NULL,
        manager_id INTEGER NOT NULL,
        action_type TEXT NOT NULL CHECK(action_type IN ('viewer','signer')),
        latest_state TEXT NOT NULL DEFAULT 'pending' CHECK(latest_state IN ('pending','approved','rejected','need_review')),
        latest_notes TEXT DEFAULT '',
        latest_signed_name TEXT DEFAULT '',
        latest_signed_at TEXT DEFAULT '',
        latest_signature_data_url TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(request_id, cycle_no, step_order),
        FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
        FOREIGN KEY(manager_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS request_step_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        cycle_no INTEGER NOT NULL,
        step_order INTEGER NOT NULL,
        manager_id INTEGER NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('approved','rejected','need_review')),
        notes TEXT DEFAULT '',
        signed_name TEXT DEFAULT '',
        signed_at TEXT DEFAULT '',
        signature_data_url TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        ip TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
        FOREIGN KEY(manager_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS manager_signatures (
        manager_id INTEGER PRIMARY KEY,
        signature_data_url TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(manager_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        request_id INTEGER DEFAULT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        actor_id INTEGER DEFAULT NULL,
        actor_role TEXT DEFAULT '',
        actor_name TEXT DEFAULT '',
        request_id INTEGER DEFAULT NULL,
        cycle_no INTEGER DEFAULT 0,
        step_order INTEGER DEFAULT 0,
        action TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '{}',
        ip TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE SET NULL
    );
    """
    db.executescript(schema)
    # migrations for existing/older app.db
    try:
        apply_db_migrations(db)
    except Exception:
        pass
    db.commit()
    db.close()


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    try:
        row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        return bool(row)
    except Exception:
        return False


def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = db.execute(f"PRAGMA table_info({table})").fetchall()
        return {r[1] for r in rows}
    except Exception:
        return set()


def _ensure_column(db: sqlite3.Connection, table: str, col: str, col_sql: str) -> None:
    if not _table_exists(db, table):
        return
    cols = _table_columns(db, table)
    if col in cols:
        return
    # SQLite: ADD COLUMN supports only simple column definitions.
    db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_sql}")


def apply_db_migrations(db: sqlite3.Connection) -> None:
    """Best-effort migrations for older DB files (no destructive changes)."""
    # Fix for: sqlite3.OperationalError: table audit_log has no column named created_at
    _ensure_column(db, "audit_log", "created_at", "TEXT")
    # Keep some safety columns if DB came from older builds
    _ensure_column(db, "users", "email", "TEXT DEFAULT ''")
    _ensure_column(db, "users", "is_active", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(db, "users", "created_at", "TEXT")
    _ensure_column(db, "requests", "meta_json", "TEXT NOT NULL DEFAULT '{}'")



def db_exec(query: str, params: Tuple[Any, ...] = ()) -> int:
    db = get_db()
    cur = db.execute(query, params)
    db.commit()
    return cur.lastrowid


def db_query_one(query: str, params: Tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
    db = get_db()
    cur = db.execute(query, params)
    return cur.fetchone()


def db_query_all(query: str, params: Tuple[Any, ...] = ()) -> List[sqlite3.Row]:
    db = get_db()
    cur = db.execute(query, params)
    return cur.fetchall()


#####################################################################################
# Auth
#####################################################################################

@dataclass
class CurrentUser:
    id: int
    username: str
    full_name: str
    email: str
    role: str


def load_current_user() -> Optional[CurrentUser]:
    uid = session.get("user_id")
    if not uid:
        return None
    row = db_query_one("SELECT * FROM users WHERE id=? AND is_active=1", (uid,))
    if not row:
        session.pop("user_id", None)
        return None
    return CurrentUser(
        id=row["id"],
        username=row["username"],
        full_name=row["full_name"],
        email=row["email"] or "",
        role=row["role"],
    )


@app.before_request
def before_request() -> None:
    g.current_user = load_current_user()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.current_user:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def role_required(*roles: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not g.current_user:
                return redirect(url_for("login", next=request.path))
            if g.current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


#####################################################################################
# Audit + Notifications + Email
#####################################################################################

def audit(action: str,
          details: Dict[str, Any] | None = None,
          request_id: int | None = None,
          cycle_no: int | None = None,
          step_order: int | None = None) -> None:
    user = g.current_user
    actor_id = user.id if user else None
    actor_role = user.role if user else ""
    actor_name = user.full_name if user else ""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ua = request.headers.get("User-Agent", "")

    db_exec(
        """INSERT INTO audit_log(created_at, actor_id, actor_role, actor_name, request_id, cycle_no, step_order, action, details, ip, user_agent)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            now_utc_iso(),
            actor_id,
            actor_role,
            actor_name,
            request_id,
            int(cycle_no or 0),
            int(step_order or 0),
            action,
            json_dumps(details or {}),
            ip,
            ua,
        ),
    )


def notify(user_id: int, title: str, message: str, request_id: Optional[int] = None) -> None:
    db_exec(
        "INSERT INTO notifications(user_id,title,message,request_id,is_read,created_at) VALUES(?,?,?,?,0,?)",
        (user_id, title, message, request_id, now_utc_iso()),
    )


def send_email(to_email: str, subject: str, html_body: str) -> None:
    """
    SMTP is optional. If not configured, we log instead of failing.
    """
    if not to_email:
        return
    if not SMTP_HOST or not SMTP_FROM:
        print(f"[EMAIL:LOG] To={to_email} Subject={subject}\n{html_body}\n")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_TLS:
                server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    except Exception:
        # Never break workflow due to email errors; keep audit log
        print("[EMAIL:ERROR] Failed to send:", to_email, subject)
        print(traceback.format_exc())


#####################################################################################
# Workflow Engine
#####################################################################################

def generate_request_no(db: sqlite3.Connection | None = None) -> str:
    """
    Format: R-YYYY-000001
    """
    year = dt.date.today().year
    prefix = f"R-{year}-"
    # find last numeric
    row = db_query_one("SELECT request_no FROM requests WHERE request_no LIKE ? ORDER BY id DESC LIMIT 1", (prefix + "%",))
    if not row:
        return prefix + "000001"
    last = row["request_no"]
    m = re.match(rf"R-{year}-(\d+)", last)
    if not m:
        return prefix + "000001"
    n = int(m.group(1)) + 1
    return prefix + f"{n:06d}"




# -------------------------------------------------------------------
# Project / Unit based request number (Decision Request No)
# Format example:
#   P1002_Cube_Decision_Request-002
# -------------------------------------------------------------------

DEFAULT_PROJECT_CHOICES = [
    {"code": "Cube", "name": "The Cube Quarter Residences"},
    {"code": "Gate_Eleven", "name": "Gate Eleven"},
    {"code": "Starlight_Park", "name": "Starlight Park"},
    {"code": "The_Cube", "name": "The Cube"},
]

# You can change these in templates as needed; backend accepts any free text too.
DEFAULT_REQUEST_TYPE_CHOICES = ["Decision Request", "Nomination", "Variation"]


def first_nonempty(*vals: Any) -> str:
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def _code_token(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    s = re.sub(r"[^A-Za-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def project_code_from_value(project_value: str) -> str:
    pv = (project_value or "").strip()
    if not pv:
        return ""
    pv_low = pv.lower()
    for it in DEFAULT_PROJECT_CHOICES:
        if pv_low == str(it["code"]).lower() or pv_low == str(it["name"]).lower():
            return str(it["code"])
    # soft matching for common words
    if "cube" in pv_low:
        return "Cube"
    if "gate" in pv_low:
        return "Gate_Eleven"
    if "starlight" in pv_low:
        return "Starlight_Park"
    return _code_token(pv)


def request_type_code(req_type: str) -> str:
    rt = (req_type or "").strip()
    if not rt:
        return ""
    # Keep the exact "Decision_Request" style used in your PDF
    rt = rt.replace("-", " ")
    return _code_token(rt)


def unit_code(unit_no: str) -> str:
    u = (unit_no or "").strip()
    if not u:
        return ""
    # Units like P1002 should stay compact (no underscores)
    u = re.sub(r"\s+", "", u)
    u = re.sub(r"[^A-Za-z0-9]+", "", u)
    return u


def generate_request_no_v2(unit_no: str, project_value: str, req_type: str) -> str:
    """
    Example: P1002_Cube_Decision_Request-002

    Sequence is per (unit, project, request_type) prefix to match your required numbering logic.
    """
    u = unit_code(unit_no)
    p = project_code_from_value(project_value)
    t = request_type_code(req_type) or "Decision_Request"

    if not (u and p):
        # fallback
        return generate_request_no()

    prefix = f"{u}_{p}_{t}-"

    row = db_query_one(
        "SELECT request_no FROM requests WHERE request_no LIKE ? ORDER BY id DESC LIMIT 1",
        (prefix + "%",),
    )
    if not row:
        return prefix + "001"

    last = str(row["request_no"])
    m = re.match(rf"{re.escape(prefix)}(\d+)$", last)
    if not m:
        return prefix + "001"
    n = int(m.group(1)) + 1
    return prefix + f"{n:03d}"
def get_workflow_template_steps() -> List[sqlite3.Row]:
    return db_query_all(
        """SELECT w.step_order, w.manager_id, w.action_type, u.full_name, u.email
           FROM workflow_template_steps w
           JOIN users u ON u.id = w.manager_id
           WHERE w.is_active=1
           ORDER BY w.step_order ASC"""
    )


def instantiate_request_steps(request_id: int,
                              cycle_no: int,
                              workflow_overrides: List[Dict[str, Any]] | None = None,
                              selected_manager_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """
    Create request_steps rows from template.
    workflow_overrides example:
      [{"manager_id": 12, "action_type":"viewer"}, {"step_order":2,"action_type":"signer"}]
    Priority:
      override by step_order if provided else by manager_id, else default.
    """
    template = get_workflow_template_steps()
    selected_set = {int(x) for x in selected_manager_ids} if selected_manager_ids else set()
    overrides = workflow_overrides or []
    by_step = {int(x.get("step_order")): x for x in overrides if x.get("step_order")}
    by_mgr = {int(x.get("manager_id")): x for x in overrides if x.get("manager_id")}

    created = []
    for t in template:
        manager_id = int(t["manager_id"])
        if selected_set and manager_id not in selected_set:
            continue

        step_order = len(created) + 1
        action_type = t["action_type"]

        if step_order in by_step and by_step[step_order].get("action_type") in ("viewer", "signer"):
            action_type = by_step[step_order]["action_type"]
        elif manager_id in by_mgr and by_mgr[manager_id].get("action_type") in ("viewer", "signer"):
            action_type = by_mgr[manager_id]["action_type"]

        ts = now_utc_iso()
        db_exec(
            """INSERT INTO request_steps(request_id,cycle_no,step_order,manager_id,action_type,latest_state,created_at,updated_at)
               VALUES(?,?,?,?,?,'pending',?,?)""",
            (request_id, cycle_no, step_order, manager_id, action_type, ts, ts),
        )
        created.append({"step_order": step_order, "manager_id": manager_id, "action_type": action_type})
    return created


def reset_steps_to_pending(request_id: int, cycle_no: int) -> None:
    ts = now_utc_iso()
    db_exec(
        """UPDATE request_steps
           SET latest_state='pending', latest_notes='', latest_signed_name='', latest_signed_at='',
               latest_signature_data_url='', updated_at=?
           WHERE request_id=? AND cycle_no=?""",
        (ts, request_id, cycle_no),
    )


def set_step_pending(request_id: int, cycle_no: int, step_order: int) -> None:
    ts = now_utc_iso()
    db_exec(
        """UPDATE request_steps
           SET latest_state='pending', latest_notes='', latest_signed_name='', latest_signed_at='',
               latest_signature_data_url='', updated_at=?
           WHERE request_id=? AND cycle_no=? AND step_order=?""",
        (ts, request_id, cycle_no, step_order),
    )


def get_request(request_id: int) -> Optional[sqlite3.Row]:
    return db_query_one("SELECT * FROM requests WHERE id=?", (request_id,))


def get_request_steps(request_id: int, cycle_no: int) -> List[sqlite3.Row]:
    return db_query_all(
        """SELECT rs.*, u.full_name as manager_name, u.email as manager_email
           FROM request_steps rs
           JOIN users u ON u.id = rs.manager_id
           WHERE rs.request_id=? AND rs.cycle_no=?
           ORDER BY rs.step_order ASC""",
        (request_id, cycle_no),
    )


def get_current_assignee_user_id(req_row: sqlite3.Row) -> Optional[int]:
    current_step = int(req_row["current_step_order"])
    if current_step <= 0:
        return int(req_row["created_by_user_id"])
    rs = db_query_one(
        "SELECT manager_id FROM request_steps WHERE request_id=? AND cycle_no=? AND step_order=?",
        (req_row["id"], int(req_row["cycle_no"]), current_step),
    )
    return int(rs["manager_id"]) if rs else None


def compute_status_label(req_row: sqlite3.Row) -> str:
    """
    User wanted:
      Pending 1/2/3...
      Approved 1/2...
      Rejected 1/2...
      Need Review 1/2...
    We'll show label based on:
      - if status == approved => Approved (Final)
      - if status == returned_to_requester => "{ReturnReasonTitle} {last_decision_step} (Returned to requester)"
      - else in_review => "Pending {current_step_order}"
    and last decision label is available separately.
    """
    status = req_row["status"]
    current_step = int(req_row["current_step_order"])
    last_dec = (req_row["last_decision"] or "").strip()
    last_step = int(req_row["last_decision_step"] or 0)

    def title(dec: str) -> str:
        if dec == DECISION_APPROVED:
            return "Approved"
        if dec == DECISION_REJECTED:
            return "Rejected"
        if dec == DECISION_NEED_REVIEW:
            return "Need Review"
        return "Pending"

    if status == REQ_APPROVED:
        return "Approved (Final)"
    if status == REQ_RETURNED:
        rr = (req_row["return_reason"] or last_dec or DECISION_NEED_REVIEW)
        step = last_step or int(req_row["return_from_step"] or 0) or 1
        return f"{title(rr)} {step} (Returned to requester)"
    if status == REQ_DRAFT:
        return "Draft"
    if status == REQ_IN_REVIEW:
        if current_step > 0:
            return f"Pending {current_step}"
        return "Pending"
    return status


def compute_last_decision_label(req_row: sqlite3.Row) -> str:
    last_dec = (req_row["last_decision"] or "").strip()
    last_step = int(req_row["last_decision_step"] or 0)
    if not last_dec or last_step <= 0:
        return ""
    if last_dec == DECISION_APPROVED:
        return f"Approved {last_step}"
    if last_dec == DECISION_REJECTED:
        return f"Rejected {last_step}"
    if last_dec == DECISION_NEED_REVIEW:
        return f"Need Review {last_step}"
    return ""


def require_signature_for_step(req_row: sqlite3.Row, step_order: int) -> bool:
    rs = db_query_one(
        """SELECT action_type FROM request_steps
           WHERE request_id=? AND cycle_no=? AND step_order=?""",
        (req_row["id"], int(req_row["cycle_no"]), step_order),
    )
    if not rs:
        return False
    return rs["action_type"] == "signer"


def get_active_managers_for_routing() -> List[Dict[str, Any]]:
    rows = db_query_all(
        """SELECT u.*, COALESCE(mp.title,'') as title, COALESCE(w.step_order,0) as workflow_step_order,
                  COALESCE(w.action_type,'signer') as workflow_action_type
           FROM users u
           LEFT JOIN manager_profiles mp ON mp.manager_id = u.id
           LEFT JOIN workflow_template_steps w ON w.manager_id = u.id AND w.is_active=1
           WHERE u.role=? AND u.is_active=1
           ORDER BY CASE WHEN w.step_order IS NULL THEN 9999 ELSE w.step_order END ASC, u.full_name ASC""",
        (ROLE_MANAGER,),
    )
    return [dict(r) for r in rows]


def parse_route_selection(form: Dict[str, Any], managers: List[Dict[str, Any]]) -> Tuple[Dict[str, str], List[int], List[int]]:
    route_map: Dict[str, str] = {}
    to_ids: List[int] = []
    cc_ids: List[int] = []
    manager_ids = [int(m.get("id")) for m in managers]
    for mid in manager_ids:
        v = (form.get(f"route_{mid}") or "").strip().lower()
        if v in ("to", "cc"):
            route_map[str(mid)] = v
            if v == "to":
                to_ids.append(mid)
            elif v == "cc":
                cc_ids.append(mid)
    return route_map, to_ids, cc_ids


def route_on_decision(req_row: sqlite3.Row, decision: str) -> Tuple[int, str]:
    """
    Returns (new_current_step_order, new_status)
    Rules:
      - Approved => forward
      - Rejected/NeedReview => backward to previous manager; if none => return to requester (current_step=0, status=returned_to_requester)
    """
    assert decision in (DECISION_APPROVED, DECISION_REJECTED, DECISION_NEED_REVIEW)
    current_step = int(req_row["current_step_order"])
    steps = get_request_steps(req_row["id"], int(req_row["cycle_no"]))
    max_step = steps[-1]["step_order"] if steps else 0

    if decision == DECISION_APPROVED:
        if current_step >= max_step:
            return (0, REQ_APPROVED)
        return (current_step + 1, REQ_IN_REVIEW)

    # rejected or need_review
    prev_step = current_step - 1
    if prev_step >= 1:
        return (prev_step, REQ_IN_REVIEW)
    return (0, REQ_RETURNED)


#####################################################################################
# Core Routes
#####################################################################################

@app.get("/")
def home():
    if not g.current_user:
        return redirect(url_for("login"))
    if g.current_user.role == ROLE_ADMIN:
        return redirect(url_for("admin_dashboard"))
    if g.current_user.role == ROLE_MANAGER:
        return redirect(url_for("inbox"))
    return redirect(url_for("request_new"))


@app.get("/requests")
@role_required(ROLE_USER)
def user_requests():
    rows = db_query_all(
        """SELECT r.*, u.full_name as requester_name
           FROM requests r
           JOIN users u ON u.id = r.created_by_user_id
           WHERE r.created_by_user_id=?
           ORDER BY r.updated_at DESC
           LIMIT 200""",
        (g.current_user.id,),
    )
    data = []
    for r in rows:
        rr = build_req_obj(r, include_steps=False)
        data.append(rr)

    # Prefer a dedicated list template if you have it; otherwise fallback to a minimal HTML table.
    for cand in ("user_requests.html", "requests_list.html", "my_requests.html"):
        if template_exists(cand):
            return render_template(cand, current_user=g.current_user, user=g.current_user, rows=data, requests=data)

    # Fallback
    html = [
        "<h2>My Requests</h2>",
        f"<p><a href='{url_for('request_new')}'>Create new request</a> | <a href='{url_for('logout')}'>Logout</a></p>",
        "<table border='1' cellpadding='6' cellspacing='0'>",
        "<tr><th>ID</th><th>Request No</th><th>Status</th><th>Updated</th><th>Actions</th></tr>",
    ]
    for r in data:
        html.append(
            f"<tr><td>{r.get('id')}</td><td>{r.get('request_no','')}</td><td>{r.get('status_label','')}</td><td>{r.get('updated_at','')}</td>"
            f"<td><a href='{url_for('request_detail', request_id=int(r.get('id')))}'>View</a> | "
            f"<a href='{url_for('request_edit', request_id=int(r.get('id')))}'>Edit</a></td></tr>"
        )
    html.append("</table>")
    return "\n".join(html)


# Backwards/Template compatibility aliases
@app.get("/my")
@role_required(ROLE_USER)
def my_requests_alias():
    return user_requests()


@app.post("/admin/reorder_managers")
@role_required(ROLE_ADMIN)
def admin_reorder_managers():
    """
    Compatibility endpoint used by older templates: url_for('admin_reorder_managers').

    Accepts either:
      - workflow_json: JSON list of steps (same as /admin/workflow/set), OR
      - manager_order / order / manager_ids: comma/space-separated manager IDs (reorders only).
    """
    # 1) If full workflow JSON provided, validate and save (same behavior as admin_set_workflow)
    raw = (
        request.form.get("workflow_json")
        or request.form.get("steps_json")
        or request.form.get("workflow")
        or ""
    ).strip()
    if raw:
        try:
            data = json.loads(raw)
            if not isinstance(data, list):
                raise ValueError("workflow must be list")
        except Exception:
            flash("Invalid workflow JSON.")
            return redirect(url_for("admin_dashboard"))

        cleaned = []
        seen_orders = set()
        for it in data:
            try:
                if not isinstance(it, dict):
                    raise ValueError("each step must be object")
                step_order = int(it.get("step_order") or 0)
                manager_id = int(it.get("manager_id") or 0)
                action_type = (it.get("action_type") or "signer").strip().lower()
                if step_order <= 0:
                    raise ValueError("step_order must be >= 1")
                if manager_id <= 0:
                    raise ValueError("manager_id must be valid")
                if action_type not in ("viewer", "signer"):
                    raise ValueError("action_type must be viewer/signer")
                if step_order in seen_orders:
                    raise ValueError("duplicate step_order")
                cleaned.append((step_order, manager_id, action_type))
                seen_orders.add(step_order)
            except Exception as e:
                flash(f"Workflow validation error: {e}")
                return redirect(url_for("admin_dashboard"))

        db_exec("UPDATE workflow_template_steps SET is_active=0")
        for step_order, manager_id, action_type in sorted(cleaned, key=lambda x: x[0]):
            db_exec(
                "INSERT INTO workflow_template_steps(step_order,manager_id,action_type,is_active,created_at) VALUES(?,?,?,1,?)",
                (step_order, manager_id, action_type, now_utc_iso()),
            )

        audit("admin.workflow.updated", {"steps": cleaned})
        flash("Managers order saved.")
        return redirect(url_for("admin_dashboard"))

    # 2) Reorder-only: accept a list of manager IDs, preserve existing action_type per manager if possible.
    order_str = (
        request.form.get("manager_order")
        or request.form.get("order")
        or request.form.get("manager_ids")
        or ""
    ).strip()

    ids = []
    if order_str:
        parts = re.split(r"[\s,]+", order_str)
        ids = [int(x) for x in parts if x.strip().isdigit()]
    else:
        # fallback: repeated fields
        ids = [int(x) for x in request.form.getlist("manager_id") if str(x).isdigit()]

    if not ids:
        flash("No managers provided to reorder.")
        return redirect(url_for("admin_dashboard"))

    # Load existing workflow to preserve each manager action_type (viewer/signer)
    existing = db_query_all(
        "SELECT manager_id, action_type FROM workflow_template_steps WHERE is_active=1 ORDER BY step_order"
    )
    action_map = {int(r["manager_id"]): (r["action_type"] or "signer") for r in existing}

    cleaned = []
    for i, mid in enumerate(ids, start=1):
        cleaned.append((i, int(mid), action_map.get(int(mid), "signer")))

    db_exec("UPDATE workflow_template_steps SET is_active=0")
    for step_order, manager_id, action_type in cleaned:
        db_exec(
            "INSERT INTO workflow_template_steps(step_order,manager_id,action_type,is_active,created_at) VALUES(?,?,?,1,?)",
            (step_order, manager_id, action_type, now_utc_iso()),
        )

    audit("admin.workflow.reordered", {"order": ids})
    flash("Managers order saved.")
    return redirect(url_for("admin_dashboard"))



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    row = db_query_one("SELECT * FROM users WHERE username=? AND is_active=1", (username,))
    if not row or not check_password_hash(row["password_hash"], password):
        flash("Invalid username or password")
        return redirect(url_for("login"))

    session["user_id"] = int(row["id"])
    audit("auth.login", {"username": username})
    nxt = request.args.get("next") or url_for("home")
    return redirect(nxt)


@app.get("/logout")
@login_required
def logout():
    audit("auth.logout", {})
    session.pop("user_id", None)
    return redirect(url_for("login"))


#####################################################################################
# User: Create/Fill Request
#####################################################################################

@app.get("/request/new")
@role_required(ROLE_USER)
def request_new():
    """
    Two-step flow support:
      1) Setup/Mask page: user selects Project / Unit / Request Type (and any other pre-fields)
      2) Full request form page with auto-filled values (request no, requester, date, etc.)

    We keep this compatible with multiple template variants by:
      - saving setup values in session["request_setup"]
      - rendering request_setup.html if present (otherwise request_form.html in mode="setup")
      - rendering request_form.html in mode="create" when setup is complete
    """
    # Merge any query-params setup values into session
    setup_from_args = extract_setup_values(request.args.to_dict(flat=True))
    setup = merge_setup_into_session(setup_from_args)

    stage = (request.args.get("stage") or request.args.get("step") or "").strip().lower()

    # Determine readiness
    project_value = (setup.get("project") or "").strip()
    unit_no = (setup.get("unit_no") or "").strip()
    req_type = (setup.get("request_type") or "").strip() or "Decision Request"
    ready = bool(project_value and unit_no and req_type)

    template_steps = get_workflow_template_steps()
    managers = get_active_managers_for_routing()

    # Preview next request number / seq for UI (not reserved until save)
    request_no_preview = ""
    next_seq = ""
    if ready:
        try:
            request_no_preview = generate_request_no_v2(unit_no, project_value, req_type)
            m = re.search(r"-(\d+)$", request_no_preview)
            if m:
                next_seq = m.group(1)
        except Exception:
            request_no_preview = ""
            next_seq = ""

    # Base req object for templates
    req_obj = {
        "id": 0,
        "request_no": request_no_preview,
        "request_type": req_type,
        "status": REQ_DRAFT,
        "status_label": "Draft",
        "last_decision_label": "",
        "header": {
            "project": project_value,
            "unit_no": unit_no,
            "request_type": req_type,
            "decision_request_no": request_no_preview,
            "request_no": request_no_preview,
            "decision_request_by": g.current_user.full_name,
            "requested_by": g.current_user.full_name,
            "requester_email": getattr(g.current_user, "email", "") or "",
            "date": today_iso(),
        },
        "mid": {},
        "meta": {},
        "steps": [
            {
                "step_order": int(s["step_order"]),
                "manager_id": int(s["manager_id"]),
                "action_type": s["action_type"],
                "manager_name": s["full_name"],
                "manager_email": s["email"],
                "latest_state": "pending",
                "latest_notes": "",
                "latest_signed_at": "",
            }
            for s in template_steps
        ],
    }

    # If setup is not complete (or explicitly asking for setup), show setup page first
    if (not ready) or stage in ("setup", "prefill", "mask", ""):
        # Choose a setup template if you have one
        setup_tpl = None
        for cand in ("request_setup.html", "request_mask.html", "request_prefill.html"):
            if template_exists(cand):
                setup_tpl = cand
                break
        if setup_tpl:
            return render_template(
                setup_tpl,
                current_user=g.current_user,
                user=g.current_user,
                mode="setup",
                stage="setup",
                setup=setup,
                prefill=setup,
                req=req_obj,
                request_obj=req_obj,
                template_steps=template_steps,
                managers=managers,
                projects=DEFAULT_PROJECT_CHOICES,
                request_type_choices=DEFAULT_REQUEST_TYPE_CHOICES,
                next_request_no=request_no_preview,
                next_seq=next_seq,
            )

        # Fallback: reuse request_form.html but in setup mode
        return render_template(
            "request_form.html",
            current_user=g.current_user,
            user=g.current_user,
            mode="setup",
            stage="setup",
            setup=setup,
            prefill=setup,
            req=req_obj,
            request_obj=req_obj,          # backward-compat
            template_steps=template_steps,
            projects=DEFAULT_PROJECT_CHOICES,
            request_type_choices=DEFAULT_REQUEST_TYPE_CHOICES,
            next_request_no=request_no_preview,
            next_seq=next_seq,
        )

    # Otherwise, show the full form in create mode
    return render_template(
        "request_form.html",
        current_user=g.current_user,
        user=g.current_user,
        mode="create",
        stage="form",
        setup=setup,
        prefill=setup,
        req=req_obj,
        request_obj=req_obj,
        template_steps=template_steps,
        managers=managers,
        projects=DEFAULT_PROJECT_CHOICES,
        request_type_choices=DEFAULT_REQUEST_TYPE_CHOICES,
        next_request_no=request_no_preview,
        next_seq=next_seq,
    )


@app.post("/request/new")
@role_required(ROLE_USER)
def request_new_post():
    """
    Handles both:
      - setup mask submission (stores session and redirects to the full form)
      - full form submission (creates draft request)
    """
    # If this is NOT the full form, treat it as setup submission
    if not looks_like_final_request_form(request.form):
        setup_from_form = extract_setup_values(request.form.to_dict(flat=True))
        merge_setup_into_session(setup_from_form)
        return redirect(url_for("request_new", stage="form"))

    # Full form -> create draft
    return request_create()

@app.post("/request/create")
@role_required(ROLE_USER)
def request_create():
    # request_type comes from your PDF-like form selection
    req_type = (
        request.form.get("request_type")
        or request.form.get("req_type")
        or request.form.get("request_kind")
        or "Decision Request"
    ).strip()

    raw_header = request.form.get("header_json")
    raw_mid = request.form.get("mid_json")
    header_json = safe_json_loads(raw_header, {})
    mid_json = safe_json_loads(raw_mid, {})

    # Pull project/unit (used for Decision Request No format)
    project_value = first_nonempty(
        request.form.get("project"),
        request.form.get("project_name"),
        request.form.get("project_code"),
        header_json.get("project"),
        header_json.get("project_name"),
        header_json.get("project_code"),
    )
    unit_no = first_nonempty(
        request.form.get("unit_no"),
        request.form.get("unit"),
        request.form.get("unit_number"),
        request.form.get("unit_id"),
        header_json.get("unit_no"),
        header_json.get("unit"),
        header_json.get("unit_number"),
    )


    # If the UI uses a pre-form/setup step, merge those values from session when missing.
    setup = session.get("request_setup") or {}
    if not isinstance(setup, dict):
        setup = {}

    # request_type: prefer explicit form value, else setup, else default
    if not req_type:
        req_type = (setup.get("request_type") or "Decision Request").strip()

    if not project_value:
        project_value = (setup.get("project") or "").strip()
    if not unit_no:
        unit_no = (setup.get("unit_no") or "").strip()


    meta_json = safe_json_loads(request.form.get("meta_json"), {})
    if not isinstance(meta_json, dict):
        meta_json = {}

    managers = get_active_managers_for_routing()
    route_map, to_ids, cc_ids = parse_route_selection(request.form, managers)
    if not to_ids:
        flash("Select at least one TO manager.")
        return redirect(url_for("request_edit", request_id=request_id))

    managers = get_active_managers_for_routing()
    route_map, to_ids, cc_ids = parse_route_selection(request.form, managers)
    if not to_ids:
        flash("Select at least one TO manager.")
        return redirect(url_for("request_new", stage="form"))

    workflow_overrides = safe_json_loads(request.form.get("workflow_overrides_json"), [])
    if not isinstance(workflow_overrides, list):
        workflow_overrides = []

    attachment_meta = []
    if "attachment" in request.files:
        f = request.files["attachment"]
        if f and f.filename:
            if not allowed_file(f.filename):
                flash("Invalid attachment file type")
                return redirect(url_for("request_new"))
            fn = secure_filename(f.filename)
            rid_tmp = uuid.uuid4().hex[:10]
            target_dir = UPLOAD_DIR / f"draft_{rid_tmp}"
            target_dir.mkdir(parents=True, exist_ok=True)
            p = target_dir / fn
            f.save(str(p))
            attachment_meta.append(
                {"name": fn, "path": str(p), "uploaded_at": now_utc_iso()}
            )

    ts = now_utc_iso()

    # Generate Decision Request No (new format) when project+unit are provided,
    # otherwise fallback to legacy R-YYYY-xxxxxx.
    if unit_no and project_value:
        request_no = generate_request_no_v2(unit_no, project_value, req_type)
    else:
        request_no = generate_request_no()

    # If the template didn't send JSON blocks, automatically capture submitted fields
    # so the PDF-like form data is not lost.
    if not raw_header:
        header_json = {}
        # common header fields (tolerant names)
        for k in (
            "subject",
            "reason_for_decision",
            "reason",
            "priority",
            "decision_due",
            "date",
            "project",
            "project_name",
            "project_code",
            "unit_no",
            "unit",
            "unit_number",
            "request_type",
        ):
            v = (request.form.get(k) or "").strip()
            if v:
                header_json[k] = v

    if not raw_mid:
        ignore = {
            "header_json",
            "mid_json",
            "meta_json",
            "workflow_overrides_json",
            "request_type",
            "req_type",
            "request_kind",
            "project",
            "project_name",
            "project_code",
            "unit_no",
            "unit",
            "unit_number",
            "unit_id",
        }
        mid_json = {}
        for k, vals in request.form.lists():
            if k in ignore:
                continue
            if k == "attachment":
                continue
            if not vals:
                continue
            mid_json[k] = vals if len(vals) > 1 else vals[0]

    # Always enforce computed/auto header values
    if not isinstance(header_json, dict):
        header_json = {}
    header_json.setdefault("project", project_value)
    header_json.setdefault("unit_no", unit_no)
    header_json.setdefault("request_no", request_no)
    header_json.setdefault("decision_request_no", request_no)
    header_json.setdefault("decision_request_by", g.current_user.full_name)
    header_json.setdefault("requested_by", g.current_user.full_name)
    header_json.setdefault("requester_email", getattr(g.current_user, "email", "") or "")
    req_date = (request.form.get("req_date") or "").strip()
    if req_date:
        header_json["date"] = req_date
        header_json["req_date"] = req_date
    header_json.setdefault("date", today_iso())
    header_json.setdefault("request_type", req_type)

    # Light meta for lists/search
    subj = first_nonempty(request.form.get("subject"), header_json.get("subject"))
    if subj:
        meta_json.setdefault("subject", subj)
    pri = first_nonempty(request.form.get("priority"), header_json.get("priority"))
    if pri:
        meta_json.setdefault("priority", pri)
    due = first_nonempty(request.form.get("decision_due"), header_json.get("decision_due"))
    if due:
        meta_json.setdefault("decision_due", due)
    if project_value:
        meta_json.setdefault("project", project_value)
    if unit_no:
        meta_json.setdefault("unit_no", unit_no)

    if isinstance(mid_json, dict):
        mid_json["route_map"] = route_map
    meta_json["route_map"] = route_map

    # Optional: build workflow overrides from form fields if JSON not provided
    if not workflow_overrides:
        tmp = []
        for k, v in request.form.items():
            vv = (v or "").strip().lower()
            if vv not in ("viewer", "signer"):
                continue
            if k.startswith("manager_action_") or k.startswith("mgr_action_"):
                # manager_action_<manager_id>
                try:
                    mid = int(k.split("_")[-1])
                    tmp.append({"manager_id": mid, "action_type": vv})
                except Exception:
                    pass
            elif k.startswith("step_action_"):
                # step_action_<step_order>
                try:
                    so = int(k.split("_")[-1])
                    tmp.append({"step_order": so, "action_type": vv})
                except Exception:
                    pass
        if tmp:
            workflow_overrides = tmp
    if route_map:
        workflow_overrides = (
            [{"manager_id": mid, "action_type": "signer"} for mid in to_ids]
            + [{"manager_id": mid, "action_type": "viewer"} for mid in cc_ids]
        )
    meta_json["workflow_overrides"] = workflow_overrides
    request_id = db_exec(
        """INSERT INTO requests(request_no,request_type,created_by_user_id,status,cycle_no,current_step_order,
                                header_json,mid_json,meta_json,attachments_json,created_at,updated_at)
           VALUES(?,?,?,?,1,0,?,?,?,?,?,?)""",
        (
            request_no,
            req_type,
            g.current_user.id,
            REQ_DRAFT,
            json_dumps(header_json),
            json_dumps(mid_json),
            json_dumps(meta_json),
            json_dumps(attachment_meta),
            ts,
            ts,
        ),
    )

    # create steps for cycle 1
    created_steps = instantiate_request_steps(request_id, 1, workflow_overrides, selected_manager_ids=to_ids)

    audit(
        "request.created",
        {"request_no": request_no, "request_type": req_type, "steps": created_steps},
        request_id=request_id,
        cycle_no=1,
        step_order=0,
    )
    # Clear setup cache after successful draft creation
    session.pop("request_setup", None)

    flash(f"Draft saved: {request_no}")
    return redirect(url_for("request_detail", request_id=request_id))


@app.get("/request/<int:request_id>")
@login_required
def request_detail(request_id: int):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)

    # Access control:
    user = g.current_user
    is_owner = user.role == ROLE_USER and int(req_row["created_by_user_id"]) == user.id
    is_admin = user.role == ROLE_ADMIN

    # manager access if they appear in steps for this request
    is_manager_in_steps = False
    if user.role == ROLE_MANAGER:
        rs = db_query_one(
            "SELECT 1 FROM request_steps WHERE request_id=? AND cycle_no=? AND manager_id=?",
            (request_id, int(req_row["cycle_no"]), user.id),
        )
        is_manager_in_steps = bool(rs)

    if not (is_owner or is_admin or is_manager_in_steps):
        abort(403)

    # Determine mode / permissions
    can_submit = is_owner and req_row["status"] in (REQ_DRAFT, REQ_RETURNED)
    can_decide = False
    require_sig = False
    current_step = int(req_row["current_step_order"])

    if user.role == ROLE_MANAGER and req_row["status"] == REQ_IN_REVIEW:
        # must be current assignee
        assignee_id = get_current_assignee_user_id(req_row)
        if assignee_id == user.id:
            can_decide = True
            require_sig = require_signature_for_step(req_row, current_step)

    # Provide dict for template
        # Build a template-friendly request object (includes header/mid/meta + flattened keys)
    req_obj = build_req_obj(req_row, include_steps=True)
# Use unified template:
    # - users and managers see the same page, but with different UI parts
    return render_template(
        "request_form.html",
        current_user=user,
        user=user,
        mode="detail",
        req=req_obj,
        request_obj=req_obj,
        can_submit=can_submit,
        can_decide=can_decide,
        require_signature=require_sig,
        can_edit=can_submit,
        projects=DEFAULT_PROJECT_CHOICES,
        request_type_choices=DEFAULT_REQUEST_TYPE_CHOICES,
        template_steps=get_workflow_template_steps(),
        managers=get_active_managers_for_routing(),
    )



@app.route("/request/<int:request_id>/edit", methods=["GET", "POST"])
@role_required(ROLE_USER)
def request_edit(request_id: int):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)
    if int(req_row["created_by_user_id"]) != g.current_user.id:
        abort(403)

    if req_row["status"] not in (REQ_DRAFT, REQ_RETURNED):
        flash("Only Draft / Returned requests can be edited.")
        return redirect(url_for("request_detail", request_id=request_id))

    if request.method == "GET":
        req_obj = build_req_obj(req_row, include_steps=True)
        return render_template(
            "request_form.html",
            current_user=g.current_user,
            user=g.current_user,
            mode="edit",
            stage="form",
            req=req_obj,
            request_obj=req_obj,
            can_submit=True,
            can_edit=True,
            projects=DEFAULT_PROJECT_CHOICES,
            request_type_choices=DEFAULT_REQUEST_TYPE_CHOICES,
            template_steps=get_workflow_template_steps(),
            managers=get_active_managers_for_routing(),
        )

    # POST -> update draft
    raw_header = request.form.get("header_json")
    raw_mid = request.form.get("mid_json")
    header_json = safe_json_loads(raw_header, {})
    mid_json = safe_json_loads(raw_mid, {})

    # Carry existing request_no + request_type (do NOT regenerate request_no here)
    request_no = str(req_row["request_no"])
    req_type = (
        (request.form.get("request_type") or request.form.get("req_type") or req_row.get("request_type") or "Decision Request").strip()
    )

    # Setup values can help if template is 2-step
    setup = session.get("request_setup") or {}
    if not isinstance(setup, dict):
        setup = {}

    project_value = first_nonempty(
        request.form.get("project"),
        request.form.get("project_name"),
        request.form.get("project_code"),
        header_json.get("project"),
        header_json.get("project_name"),
        header_json.get("project_code"),
        setup.get("project"),
        safe_json_loads(req_row["header_json"], {}).get("project"),
    )
    unit_no = first_nonempty(
        request.form.get("unit_no"),
        request.form.get("unit"),
        request.form.get("unit_number"),
        request.form.get("unit_id"),
        header_json.get("unit_no"),
        header_json.get("unit"),
        header_json.get("unit_number"),
        setup.get("unit_no"),
        safe_json_loads(req_row["header_json"], {}).get("unit_no"),
    )

    meta_json = safe_json_loads(request.form.get("meta_json"), {})
    if not isinstance(meta_json, dict):
        meta_json = {}

    # If JSON blocks are absent, capture submitted fields
    if not raw_header:
        header_json = {}
        for k in (
            "subject",
            "reason_for_decision",
            "reason",
            "priority",
            "decision_due",
            "date",
            "project",
            "project_name",
            "project_code",
            "unit_no",
            "unit",
            "unit_number",
            "request_type",
        ):
            v = (request.form.get(k) or "").strip()
            if v:
                header_json[k] = v

    if not raw_mid:
        ignore = {
            "header_json",
            "mid_json",
            "meta_json",
            "workflow_overrides_json",
            "request_type",
            "req_type",
            "request_kind",
            "project",
            "project_name",
            "project_code",
            "unit_no",
            "unit",
            "unit_number",
            "unit_id",
        }
        mid_json = {}
        for k, vals in request.form.lists():
            if k in ignore or k == "attachment":
                continue
            if not vals:
                continue
            mid_json[k] = vals if len(vals) > 1 else vals[0]

    # Enforce computed/auto header values
    if not isinstance(header_json, dict):
        header_json = {}
    header_json.setdefault("project", (project_value or "").strip())
    header_json.setdefault("unit_no", (unit_no or "").strip())
    header_json.setdefault("request_no", request_no)
    header_json.setdefault("decision_request_no", request_no)
    header_json.setdefault("request_type", req_type)
    header_json.setdefault("decision_request_by", g.current_user.full_name)
    header_json.setdefault("requested_by", g.current_user.full_name)
    header_json.setdefault("requester_email", getattr(g.current_user, "email", "") or "")
    req_date = (request.form.get("req_date") or "").strip()
    if req_date:
        header_json["date"] = req_date
        header_json["req_date"] = req_date
    header_json.setdefault("date", header_json.get("date") or today_iso())

    # Update meta for lists/search
    subj = first_nonempty(request.form.get("subject"), header_json.get("subject"))
    if subj:
        meta_json["subject"] = subj
    pri = first_nonempty(request.form.get("priority"), header_json.get("priority"))
    if pri:
        meta_json["priority"] = pri
    due = first_nonempty(request.form.get("decision_due"), header_json.get("decision_due"))
    if due:
        meta_json["decision_due"] = due
    if project_value:
        meta_json["project"] = project_value
    if unit_no:
        meta_json["unit_no"] = unit_no

    if isinstance(mid_json, dict):
        mid_json["route_map"] = route_map
    meta_json["route_map"] = route_map

    workflow_overrides = (
        [{"manager_id": mid, "action_type": "signer"} for mid in to_ids]
        + [{"manager_id": mid, "action_type": "viewer"} for mid in cc_ids]
    )
    meta_json["workflow_overrides"] = workflow_overrides

    # Attachments: keep existing + append new
    attachments = safe_json_loads(req_row["attachments_json"], []) or []
    if not isinstance(attachments, list):
        attachments = []
    if "attachment" in request.files:
        f = request.files["attachment"]
        if f and f.filename:
            if not allowed_file(f.filename):
                flash("Invalid attachment file type")
                return redirect(url_for("request_edit", request_id=request_id))
            fn = secure_filename(f.filename)
            target_dir = UPLOAD_DIR / f"request_{request_id}"
            target_dir.mkdir(parents=True, exist_ok=True)
            p = target_dir / fn
            f.save(str(p))
            attachments.append({"name": fn, "path": str(p), "uploaded_at": now_utc_iso()})

    ts = now_utc_iso()
    db_exec(
        """UPDATE requests
           SET request_type=?, header_json=?, mid_json=?, meta_json=?, attachments_json=?, updated_at=?
           WHERE id=?""",
        (
            req_type,
            json_dumps(header_json),
            json_dumps(mid_json),
            json_dumps(meta_json),
            json_dumps(attachments),
            ts,
            request_id,
        ),
    )

    db_exec("DELETE FROM request_steps WHERE request_id=? AND cycle_no=?", (request_id, int(req_row["cycle_no"])))
    instantiate_request_steps(request_id, int(req_row["cycle_no"]), workflow_overrides, selected_manager_ids=to_ids)

    audit("request.edited", {"request_no": request_no, "request_type": req_type}, request_id=request_id, cycle_no=int(req_row["cycle_no"]), step_order=int(req_row["current_step_order"]))

    flash("Draft updated.")
    return redirect(url_for("request_detail", request_id=request_id))


@app.post("/request/<int:request_id>/submit")
@role_required(ROLE_USER)
def request_submit(request_id: int):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)
    if int(req_row["created_by_user_id"]) != g.current_user.id:
        abort(403)
    if req_row["status"] not in (REQ_DRAFT, REQ_RETURNED):
        flash("Request cannot be submitted in current status.")
        return redirect(url_for("request_detail", request_id=request_id))

    # If returned_to_requester, it's a new cycle upon resubmission
    cycle_no = int(req_row["cycle_no"])
    if req_row["status"] == REQ_RETURNED:
        cycle_no += 1

        # increment cycle, create new steps from template (use same overrides from meta if present)
        meta = safe_json_loads(req_row["meta_json"], {})
        workflow_overrides = meta.get("workflow_overrides") or []
        selected_signers = [int(x.get("manager_id")) for x in workflow_overrides if x.get("action_type") == "signer" and x.get("manager_id")]
        db_exec(
            "UPDATE requests SET cycle_no=?, return_reason='', return_from_step=0 WHERE id=?",
            (cycle_no, request_id),
        )

        # instantiate new cycle steps
        instantiate_request_steps(request_id, cycle_no, workflow_overrides, selected_manager_ids=selected_signers)
        audit("request.cycle.increment", {"new_cycle": cycle_no}, request_id=request_id, cycle_no=cycle_no)

    # Start review at step 1
    ts = now_utc_iso()
    db_exec(
        """UPDATE requests
           SET status=?, current_step_order=1, last_decision='', last_decision_step=0, last_decision_by=0,
               return_reason='', return_from_step=0, updated_at=?
           WHERE id=?""",
        (REQ_IN_REVIEW, ts, request_id),
    )
    # ensure step 1 pending for this cycle
    set_step_pending(request_id, cycle_no, 1)

    audit("request.submitted", {"cycle_no": cycle_no}, request_id=request_id, cycle_no=cycle_no, step_order=1)

    # notify first manager
    first = db_query_one(
        """SELECT rs.manager_id, u.full_name, u.email
           FROM request_steps rs JOIN users u ON u.id = rs.manager_id
           WHERE rs.request_id=? AND rs.cycle_no=? AND rs.step_order=1""",
        (request_id, cycle_no),
    )
    if first:
        notify(int(first["manager_id"]), "New approval request", f"Request #{req_row['request_no']} needs your action (Step 1).", request_id)
        send_email(first["email"] or "", f"[{APP_NAME}] Approval needed: {req_row['request_no']}",
                   f"<p>Request <b>{req_row['request_no']}</b> needs your action (Step 1).</p>")

    flash("Submitted for approval.")
    return redirect(url_for("request_detail", request_id=request_id))


#####################################################################################
# Manager: Inbox + Decision
#####################################################################################


@app.get("/inbox")
@role_required(ROLE_MANAGER)
def inbox():
    # Requests assigned to this manager at current step (current cycle)
    rows = db_query_all(
        """
        SELECT r.*, u.full_name as requester_name, u.email as requester_email
        FROM requests r
        JOIN users u ON u.id = r.created_by_user_id
        WHERE r.status=? AND
              EXISTS (
                SELECT 1 FROM request_steps rs
                WHERE rs.request_id=r.id AND rs.cycle_no=r.cycle_no AND rs.step_order=r.current_step_order AND rs.manager_id=?
              )
        ORDER BY r.updated_at DESC
        """,
        (REQ_IN_REVIEW, g.current_user.id),
    )

    data = [build_req_obj(r, include_steps=False) for r in rows]

    for cand in ("manager_inbox.html", "inbox.html", "request_view.html"):
        if template_exists(cand):
            return render_template(cand, current_user=g.current_user, user=g.current_user, rows=data, requests=data, inbox=data)

    # Fallback minimal HTML
    html = [
        "<h2>Manager Inbox</h2>",
        f"<p><a href='{url_for('logout')}'>Logout</a></p>",
        "<table border='1' cellpadding='6' cellspacing='0'>",
        "<tr><th>ID</th><th>Request No</th><th>Requester</th><th>Status</th><th>Step</th><th>Updated</th><th>Action</th></tr>",
    ]
    for r in data:
        html.append(
            f"<tr><td>{r.get('id')}</td><td>{r.get('request_no','')}</td><td>{r.get('requester_name','')}</td>"
            f"<td>{r.get('status_label','')}</td><td>{r.get('current_step_order','')}</td><td>{r.get('updated_at','')}</td>"
            f"<td><a href='{url_for('request_detail', request_id=int(r.get('id')))}'>Open</a></td></tr>"
        )
    html.append("</table>")
    return "\n".join(html)


@app.get("/manager/inbox")
@role_required(ROLE_MANAGER)
def manager_inbox():
    return inbox()


@app.post("/request/<int:request_id>/decide")
@role_required(ROLE_MANAGER)
def request_decide(request_id: int):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)
    if req_row["status"] != REQ_IN_REVIEW:
        flash("Request is not currently in review.")
        return redirect(url_for("request_detail", request_id=request_id))

    cycle_no = int(req_row["cycle_no"])
    current_step = int(req_row["current_step_order"])
    assignee_id = get_current_assignee_user_id(req_row)
    if assignee_id != g.current_user.id:
        abort(403)

    
    # Support multiple template field names for compatibility
    decision_raw = first_nonempty(
        request.form.get("decision"),
        request.form.get(f"decision_{g.current_user.id}"),
        request.form.get(f"mgr_decision_{g.current_user.id}"),
        request.form.get("manager_decision"),
        request.form.get("action"),
    ) or ""
    decision = decision_raw.strip().lower()

    # Normalize common variants
    if decision in ("approve", "approved", "yes", "ok"):
        decision = DECISION_APPROVED
    elif decision in ("reject", "rejected", "no"):
        decision = DECISION_REJECTED
    elif decision in ("needreview", "need_review", "need-review", "review", "return", "returned", "revise"):
        decision = DECISION_NEED_REVIEW

    if decision not in (DECISION_APPROVED, DECISION_REJECTED, DECISION_NEED_REVIEW):
        flash("Invalid decision.")
        return redirect(url_for("request_detail", request_id=request_id))

    notes = (first_nonempty(
        request.form.get("notes"),
        request.form.get("comment"),
        request.form.get("comments"),
        request.form.get(f"notes_{g.current_user.id}"),
        request.form.get(f"comment_{g.current_user.id}"),
    ) or "").strip()

    sig_raw = first_nonempty(
        request.form.get("signature_data_url"),
        request.form.get("signature_data"),
        request.form.get("sig_data_url"),
        request.form.get(f"signature_data_{g.current_user.id}"),
        request.form.get(f"sig_{g.current_user.id}"),
    ) or ""
    signature_data_url = normalize_data_url_png(sig_raw.strip())

    save_default = (first_nonempty(
        request.form.get("save_default"),
        request.form.get("save_signature"),
        request.form.get("save_default_signature"),
    ) or "") == "1"

    # signature required?
    needs_sig = require_signature_for_step(req_row, current_step)
    if needs_sig:
        if not signature_data_url:
            # fallback to default signature if exists
            sig_row = db_query_one("SELECT signature_data_url FROM manager_signatures WHERE manager_id=?", (g.current_user.id,))
            if sig_row:
                signature_data_url = sig_row["signature_data_url"]
        if not signature_data_url:
            flash("Signature is required for this step.")
            return redirect(url_for("request_detail", request_id=request_id))

    # save default signature if asked
    if needs_sig and save_default and signature_data_url:
        ts = now_utc_iso()
        # upsert
        existing = db_query_one("SELECT manager_id FROM manager_signatures WHERE manager_id=?", (g.current_user.id,))
        if existing:
            db_exec("UPDATE manager_signatures SET signature_data_url=?, updated_at=? WHERE manager_id=?",
                    (signature_data_url, ts, g.current_user.id))
        else:
            db_exec("INSERT INTO manager_signatures(manager_id, signature_data_url, updated_at) VALUES(?,?,?)",
                    (g.current_user.id, signature_data_url, ts))
        audit("signature.default.saved", {"manager_id": g.current_user.id}, request_id=request_id, cycle_no=cycle_no, step_order=current_step)

    # record action
    signed_name = g.current_user.full_name
    signed_at = today_iso()

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ua = request.headers.get("User-Agent", "")

    db_exec(
        """INSERT INTO request_step_actions(request_id,cycle_no,step_order,manager_id,decision,notes,signed_name,signed_at,signature_data_url,created_at,ip,user_agent)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (request_id, cycle_no, current_step, g.current_user.id, decision, notes, signed_name, signed_at, signature_data_url, now_utc_iso(), ip, ua),
    )

    # update latest in request_steps
    ts = now_utc_iso()
    db_exec(
        """UPDATE request_steps
           SET latest_state=?, latest_notes=?, latest_signed_name=?, latest_signed_at=?, latest_signature_data_url=?, updated_at=?
           WHERE request_id=? AND cycle_no=? AND step_order=?""",
        (decision, notes, signed_name, signed_at, signature_data_url, ts, request_id, cycle_no, current_step),
    )

    # update request routing
    new_step, new_status = route_on_decision(req_row, decision)

    # If moving forward to next step, mark that next step as pending again (in case it had prior reject/need_review)
    if new_status == REQ_IN_REVIEW and new_step > 0:
        set_step_pending(request_id, cycle_no, new_step)

    # request metadata update
    last_decision_step = current_step
    db_exec(
        """UPDATE requests
           SET status=?, current_step_order=?, last_decision=?, last_decision_step=?, last_decision_by=?,
               return_reason=?, return_from_step=?, updated_at=?
           WHERE id=?""",
        (
            new_status,
            new_step,
            decision,
            last_decision_step,
            g.current_user.id,
            (decision if decision in (DECISION_REJECTED, DECISION_NEED_REVIEW) else ""),
            (current_step if decision in (DECISION_REJECTED, DECISION_NEED_REVIEW) else 0),
            ts,
            request_id,
        ),
    )

    audit(
        "workflow.decision",
        {
            "decision": decision,
            "notes": notes,
            "from_step": current_step,
            "to_step": new_step,
            "new_status": new_status,
            "cycle_no": cycle_no,
        },
        request_id=request_id,
        cycle_no=cycle_no,
        step_order=current_step,
    )

    # Notifications / emails
    # 1) notify requester always about decision
    requester = db_query_one("SELECT id, full_name, email FROM users WHERE id=?", (int(req_row["created_by_user_id"]),))
    if requester:
        notify(int(requester["id"]), "Request update",
               f"Request #{req_row['request_no']} - {decision.upper()} at step {current_step}.", request_id)
        send_email(requester["email"] or "",
                   f"[{APP_NAME}] Update: {req_row['request_no']}",
                   f"<p>Request <b>{req_row['request_no']}</b> decision at step <b>{current_step}</b>: <b>{decision.upper()}</b>.</p>")

    # 2) route to next assignee (manager or requester)
    if new_status == REQ_APPROVED:
        # final approval -> notify all managers in chain too
        steps = get_request_steps(request_id, cycle_no)
        for s in steps:
            notify(int(s["manager_id"]), "Request completed",
                   f"Request #{req_row['request_no']} is fully approved.", request_id)
            send_email(s["manager_email"] or "",
                       f"[{APP_NAME}] Completed: {req_row['request_no']}",
                       f"<p>Request <b>{req_row['request_no']}</b> is fully approved.</p>")
        flash("Decision recorded. Request is fully approved.")
    elif new_status == REQ_RETURNED:
        notify(int(req_row["created_by_user_id"]), "Action required",
               f"Request #{req_row['request_no']} returned to you due to {decision.upper()} at step {current_step}.", request_id)
        flash("Decision recorded. Returned to requester.")
    else:
        # in_review routed to manager at new_step
        assignee = db_query_one(
            """SELECT rs.manager_id, u.full_name, u.email
               FROM request_steps rs JOIN users u ON u.id=rs.manager_id
               WHERE rs.request_id=? AND rs.cycle_no=? AND rs.step_order=?""",
            (request_id, cycle_no, new_step),
        )
        if assignee:
            direction = "next" if decision == DECISION_APPROVED else "previous"
            notify(int(assignee["manager_id"]), "Approval request",
                   f"Request #{req_row['request_no']} needs your action (Step {new_step}) ({direction} routing).", request_id)
            send_email(assignee["email"] or "",
                       f"[{APP_NAME}] Action needed: {req_row['request_no']}",
                       f"<p>Request <b>{req_row['request_no']}</b> needs your action (Step <b>{new_step}</b>).</p>")
        flash("Decision recorded.")

    return redirect(url_for("request_detail", request_id=request_id))


#####################################################################################
# Admin: Dashboard + Workflow + Users
#####################################################################################


@app.get("/admin")
@role_required(ROLE_ADMIN)
def admin_dashboard():
    # Workflow JSON + Users + Recent requests + Audit log
    audits = db_query_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100")

    weasyprint_ok = False

    template = get_workflow_template_steps()
    workflow_json = []
    for t in template:
        workflow_json.append(
            {
                "step_order": int(t["step_order"]),
                "manager_id": int(t["manager_id"]),
                "manager_name": t["full_name"],
                "action_type": t["action_type"],
            }
        )

    users = db_query_all("SELECT * FROM users ORDER BY id DESC LIMIT 500")
    managers = db_query_all(
        """SELECT u.*,
                  COALESCE(mp.title,'') as title,
                  COALESCE(w.step_order,0) as workflow_step_order,
                  COALESCE(w.step_order,0) as order_index,
                  COALESCE(w.action_type,'') as workflow_action_type
           FROM users u
           LEFT JOIN manager_profiles mp ON mp.manager_id = u.id
           LEFT JOIN workflow_template_steps w ON w.manager_id = u.id AND w.is_active=1
           WHERE u.role=? AND u.is_active=1
           ORDER BY CASE WHEN w.step_order IS NULL THEN 9999 ELSE w.step_order END ASC, u.full_name ASC""",
        (ROLE_MANAGER,),
    )

    req_rows = db_query_all(
        """SELECT r.*, u.full_name as requester_name, u.email as requester_email
           FROM requests r
           JOIN users u ON u.id = r.created_by_user_id
           ORDER BY r.updated_at DESC
           LIMIT 200"""
    )
    reqs = [build_req_obj(r, include_steps=False) for r in req_rows]

    return render_template(
        "admin.html",
        workflow_json=json.dumps(workflow_json, indent=2, ensure_ascii=False),
        audits=[dict(a) for a in audits],
        users=[dict(u) for u in users],
        managers=[dict(m) for m in managers],
        requests=reqs,
        reqs=reqs,
        email_enabled=bool(SMTP_HOST and SMTP_USER),
        weasyprint_ok=weasyprint_ok,
        db_path=str(DB_PATH),
    )


@app.get("/admin/dashboard")
@role_required(ROLE_ADMIN)
def admin_dashboard_alias():
    return admin_dashboard()


@app.get("/admin/logs")
@role_required(ROLE_ADMIN)
def admin_logs():
    rows = db_query_all(
        """SELECT al.*, u.username AS actor_username
           FROM audit_log al
           LEFT JOIN users u ON u.id = al.actor_id
           ORDER BY al.id DESC
           LIMIT 300"""
    )

    data = []
    for r in rows:
        details_obj = safe_json_loads(r["details"], {})
        data.append(
            {
                "ts": r["created_at"],
                "actor_username": r["actor_username"] or r["actor_name"] or "",
                "action": r["action"],
                "request_id": r["request_id"],
                "ip": r["ip"],
                "details_json": json_dumps(details_obj),
            }
        )

    return render_template(
        "admin_logs.html",
        current_user=g.current_user,
        user=g.current_user,
        rows=data,
        req={},
    )


@app.post("/admin/users/create")
@role_required(ROLE_ADMIN)
def admin_create_user():
    """
    Create a user (admin/manager/user) from Admin Dashboard.
    MUST ALWAYS return a valid response (redirect/render), never None.
    """
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    role = (request.form.get("role") or "").strip().lower()
    title = (request.form.get("title") or "").strip()
    order_index_raw = (request.form.get("order_index") or "").strip()
    order_index = None
    if order_index_raw:
        try:
            order_index = int(order_index_raw)
            if order_index <= 0:
                order_index = None
        except Exception:
            order_index = None

    # Basic validation
    if role not in (ROLE_ADMIN, ROLE_MANAGER, ROLE_USER):
        flash("Invalid role", "danger")
        return redirect(url_for("admin_dashboard"))

    if not username or not password or not full_name:
        flash("Missing required fields (username, password, full name).", "danger")
        return redirect(url_for("admin_dashboard"))

    if len(username) < 3:
        flash("Username must be at least 3 characters.", "danger")
        return redirect(url_for("admin_dashboard"))

    # Create in DB
    try:
        ts = now_utc_iso()
        # unique username
        exists = db_query_one("SELECT id FROM users WHERE lower(username)=lower(?)", (username,))
        if exists:
            flash("Username already exists.", "danger")
            return redirect(url_for("admin_dashboard"))

        # insert user
        new_id = db_exec(
            "INSERT INTO users(username,password_hash,full_name,email,role,is_active,created_at) VALUES(?,?,?,?,?,1,?)",
            (username, generate_password_hash(password), full_name, email, role, ts),
        )

        # manager profile row (optional)
        if role == ROLE_MANAGER:
            # create/ensure profile
            db_exec(
                "INSERT OR IGNORE INTO manager_profiles(manager_id,title,created_at,updated_at) VALUES(?,?,?,?)",
                (int(new_id), title, ts, ts),
            )
            db_exec(
                "UPDATE manager_profiles SET title=?, updated_at=? WHERE manager_id=?",
                (title, ts, int(new_id)),
            )

            # auto-append to workflow template so managers are visible in dashboard ordering
            max_row = db_query_one(
                "SELECT MAX(step_order) AS max_order FROM workflow_template_steps WHERE is_active=1",
            )
            next_order = int(max_row["max_order"] or 0) + 1
            step_order = order_index or next_order
            db_exec(
                "INSERT INTO workflow_template_steps(step_order,manager_id,action_type,is_active,created_at) VALUES(?,?,?,1,?)",
                (step_order, int(new_id), "signer", ts),
            )

        audit(
            "admin_create_user",
            request_id=None,
            details={
                "user_id": int(new_id),
                "username": username,
                "role": role,
                "order_index": order_index,
                "title": title,
            },
        )

        flash(f"Created {role}: {full_name} ({username})", "success")
        return redirect(url_for("admin_dashboard"))

    except Exception as e:
        # Never crash the view into None
        try:
            audit("admin_create_user_failed", request_id=None, details={"error": str(e), "username": username, "role": role})
        except Exception:
            pass
        flash(f"Create user failed: {e}", "danger")
        return redirect(url_for("admin_dashboard"))


@app.post("/admin/workflow/set")
@role_required(ROLE_ADMIN)
def admin_set_workflow():
    """
    Accept JSON list like:
    [
      {"step_order":1,"manager_id":2,"action_type":"signer"},
      {"step_order":2,"manager_id":5,"action_type":"viewer"}
    ]
    """
    raw = request.form.get("workflow_json") or "[]"
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("workflow must be list")
    except Exception:
        flash("Invalid JSON")
        return redirect(url_for("admin_dashboard"))

    # validate
    cleaned = []
    seen_orders = set()
    for item in data:
        try:
            step_order = int(item.get("step_order"))
            manager_id = int(item.get("manager_id"))
            action_type = (item.get("action_type") or "viewer").strip()
            if step_order <= 0 or step_order in seen_orders:
                raise ValueError("invalid step_order")
            if action_type not in ("viewer", "signer"):
                raise ValueError("invalid action_type")
            mgr = db_query_one("SELECT id, role FROM users WHERE id=? AND is_active=1", (manager_id,))
            if not mgr or mgr["role"] != ROLE_MANAGER:
                raise ValueError(f"manager_id {manager_id} is not an active manager")
            cleaned.append((step_order, manager_id, action_type))
            seen_orders.add(step_order)
        except Exception as e:
            flash(f"Workflow validation error: {e}")
            return redirect(url_for("admin_dashboard"))

    # overwrite template steps (soft reset)
    db_exec("UPDATE workflow_template_steps SET is_active=0")
    for step_order, manager_id, action_type in sorted(cleaned, key=lambda x: x[0]):
        db_exec(
            "INSERT INTO workflow_template_steps(step_order,manager_id,action_type,is_active,created_at) VALUES(?,?,?,1,?)",
            (step_order, manager_id, action_type, now_utc_iso()),
        )

    audit("admin.workflow.updated", {"steps": cleaned})
    flash("Workflow saved.")
    return redirect(url_for("admin_dashboard"))


#####################################################################################
# Report (list + filters)
#####################################################################################


@app.get("/report")
@login_required
def report():
    """Report list (filters). Safe fallback if templates differ."""
    user = g.current_user
    q = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "").strip()

    where = []
    params: List[Any] = []

    if status:
        where.append("r.status=?")
        params.append(status)

    if q:
        where.append("(lower(r.request_no) LIKE ? OR lower(r.request_type) LIKE ? OR lower(u.full_name) LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    if user.role == ROLE_MANAGER:
        # managers: show requests where they are in workflow steps
        where.append(
            """EXISTS (
                  SELECT 1 FROM request_steps rs
                  WHERE rs.request_id=r.id AND rs.manager_id=?
               )"""
        )
        params.append(user.id)
    elif user.role == ROLE_USER:
        where.append("r.created_by_user_id=?")
        params.append(user.id)

    sql = (
        """SELECT r.id, r.request_no, r.request_type, r.status, r.updated_at, r.cycle_no, u.full_name as requester_name
           FROM requests r
           JOIN users u ON u.id=r.created_by_user_id"""
        + ((" WHERE " + " AND ".join(where)) if where else "")
        + " ORDER BY r.updated_at DESC LIMIT 300"
    )

    rows = db_query_all(sql, tuple(params))
    out = []
    for r in rows:
        r_full = get_request(int(r["id"]))
        out.append(
            {
                "id": int(r["id"]),
                "request_no": r["request_no"],
                "request_type": r["request_type"],
                "requester_name": r["requester_name"],
                "status": r["status"],
                "status_label": compute_status_label(r_full) if r_full else r["status"],
                "last_decision_label": compute_last_decision_label(r_full) if r_full else "",
                "updated_at": r["updated_at"],
                "cycle_no": int(r["cycle_no"]),
            }
        )

    # Prefer a dedicated list template if present; otherwise use a minimal HTML fallback.
    if template_exists("report_list.html"):
        return render_template("report_list.html", current_user=user, user=user, rows=out, statuses=sorted(REQ_STATUSES), q=q, status=status)

    html = [
        "<h2>Report</h2>",
        f"<p><a href='{url_for('home')}'>Home</a> | <a href='{url_for('logout')}'>Logout</a></p>",
        "<form method='get'>",
        f"Search: <input name='q' value='{escape(q)}'/> ",
        "Status: <select name='status'>",
        "<option value=''>All</option>",
    ]
    for st in sorted(REQ_STATUSES):
        sel = "selected" if st == status else ""
        html.append(f"<option value='{st}' {sel}>{st}</option>")
    html.append("</select> <button type='submit'>Filter</button></form>")
    html.append("<table border='1' cellpadding='6' cellspacing='0'>")
    html.append("<tr><th>ID</th><th>Request No</th><th>Requester</th><th>Status</th><th>Updated</th><th>Open</th></tr>")
    for r in out:
        html.append(
            f"<tr><td>{r['id']}</td><td>{escape(str(r.get('request_no','')))}</td><td>{escape(str(r.get('requester_name','')))}</td>"
            f"<td>{escape(str(r.get('status_label','')))}</td><td>{escape(str(r.get('updated_at','')))}</td>"
            f"<td><a href='{url_for('report_view', request_id=int(r['id']))}'>View</a></td></tr>"
        )
    html.append("</table>")
    return "\n".join(html)


@app.get("/report/<int:request_id>")
@login_required
def report_view(request_id: int):
    """Single request report view (uses report.html if present)."""
    req_row = get_request(request_id)
    if not req_row:
        abort(404)

    user = g.current_user
    is_owner = int(req_row["created_by_user_id"]) == user.id
    is_admin = user.role == ROLE_ADMIN
    is_mgr = user.role == ROLE_MANAGER

    if not (is_owner or is_admin):
        if is_mgr:
            in_chain = db_query_one(
                "SELECT 1 FROM request_steps WHERE request_id=? AND manager_id=? LIMIT 1",
                (request_id, user.id),
            )
            if not in_chain:
                abort(403)
        else:
            abort(403)

    req_obj = build_req_obj(req_row, include_steps=True)

    if template_exists("report.html"):
        return render_template("report.html", current_user=user, user=user, req=req_obj, request_obj=req_obj)

    # Fallback to the unified request page if no dedicated report template exists
    return redirect(url_for("request_detail", request_id=request_id))


@app.get("/report/<int:request_id>/pdf")
@login_required
def report_pdf(request_id: int):
    """Alias -> audit certificate PDF."""
    return redirect(url_for("export_audit_pdf", request_id=request_id))


@app.get("/report/<int:request_id>/form.pdf")
@login_required
def report_form_pdf(request_id: int):
    """Alias -> decision request form PDF."""
    return redirect(url_for("export_form_pdf", request_id=request_id))


@app.get("/report/<int:request_id>/audit.pdf")
@login_required
def report_audit_pdf(request_id: int):
    """Alias -> audit certificate PDF."""
    return redirect(url_for("export_audit_pdf", request_id=request_id))


#####################################################################################
# Notifications
#####################################################################################

@app.get("/notifications")
@login_required
def notifications():
    rows = db_query_all(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 200",
        (g.current_user.id,),
    )
    return jsonify([dict(r) for r in rows])


@app.post("/notifications/<int:notif_id>/read")
@login_required
def notifications_mark_read(notif_id: int):
    # can only mark own
    row = db_query_one("SELECT * FROM notifications WHERE id=? AND user_id=?", (notif_id, g.current_user.id))
    if not row:
        abort(404)
    db_exec("UPDATE notifications SET is_read=1 WHERE id=?", (notif_id,))
    return jsonify({"ok": True})


#####################################################################################
# File download (attachments)
#####################################################################################

@app.get("/request/<int:request_id>/attachments/<path:filename>")
@login_required
def download_attachment(request_id: int, filename: str):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)

    # same access rules as request_detail
    user = g.current_user
    is_owner = user.role == ROLE_USER and int(req_row["created_by_user_id"]) == user.id
    is_admin = user.role == ROLE_ADMIN

    is_manager_in_steps = False
    if user.role == ROLE_MANAGER:
        rs = db_query_one(
            "SELECT 1 FROM request_steps WHERE request_id=? AND cycle_no=? AND manager_id=?",
            (request_id, int(req_row["cycle_no"]), user.id),
        )
        is_manager_in_steps = bool(rs)

    if not (is_owner or is_admin or is_manager_in_steps):
        abort(403)

    attachments = safe_json_loads(req_row["attachments_json"], [])
    for a in attachments:
        if a.get("name") == filename:
            p = Path(a.get("path") or "")
            if p.exists():
                return send_file(str(p), as_attachment=True, download_name=filename)
    abort(404)


#####################################################################################
# PDF Export
#####################################################################################

def draw_wrapped_text(c: canvas.Canvas, x: float, y: float, text: str, max_width: float, line_height: float, max_lines: int = 8):
    """
    Draw wrapped text downwards from (x,y). Returns new y.
    """
    text = (text or "").strip()
    if not text:
        return y
    # crude wrapping by characters
    # For precise wrapping you can measure strings; this is good enough for export.
    chars_per_line = max(10, int(max_width / 5.5))
    lines = textwrap.wrap(text, width=chars_per_line)[:max_lines]
    for ln in lines:
        c.drawString(x, y, ln)
        y -= line_height
    return y


def generate_form_pdf_bytes(req_row: sqlite3.Row) -> bytes:
    """
    Export a 1-page Decision Request Form PDF.
    Later you can overlay on FORM_TEMPLATE_PDF for perfect 1:1 coordinates.
    For now this produces a clean form-like PDF with the stored fields.
    """
    header = safe_json_loads(req_row["header_json"], {})
    mid = safe_json_loads(req_row["mid_json"], {})
    meta = safe_json_loads(req_row["meta_json"], {})

    steps = get_request_steps(req_row["id"], int(req_row["cycle_no"]))

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    # Title header
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20 * mm, h - 18 * mm, "Decision Request Form")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, h - 25 * mm, f"Decision Request No: {req_row['request_no']}")

    # Meta fields
    c.drawString(20 * mm, h - 32 * mm, f"Date: {header.get('date','')}")
    c.drawString(70 * mm, h - 32 * mm, f"Priority: {header.get('priority','')}")
    c.drawString(120 * mm, h - 32 * mm, f"Decision due: {header.get('decision_due','')}")

    # Section 1
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, h - 42 * mm, "1. Short Description")
    c.setFont("Helvetica", 10)
    draw_wrapped_text(c, 20 * mm, h - 48 * mm, str(mid.get("short_description", "")), 170 * mm, 4.2 * mm, max_lines=6)

    # Section 2
    y2 = h - 78 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, y2, "2. Financial & Cost Impact (YES/NO)")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y2 - 6 * mm, f"YES: {mid.get('financial_yes','')}   NO: {mid.get('financial_no','')}")
    c.drawString(20 * mm, y2 - 12 * mm, f"BOQ Cost (AED): {mid.get('boq_cost_aed','')}")
    c.drawString(70 * mm, y2 - 12 * mm, f"Proposed Contractor Value (AED): {mid.get('proposed_value_aed','')}")
    c.drawString(140 * mm, y2 - 12 * mm, f"Variance (AED): {mid.get('variance_aed','')}")

    # Section 3/4
    y3 = y2 - 24 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, y3, "3. Program & Impact on Completion Date (YES/NO)")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y3 - 6 * mm, f"YES: {mid.get('program_yes','')}   NO: {mid.get('program_no','')}")

    y4 = y3 - 16 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, y4, "4. Quality Impact (YES/NO)")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y4 - 6 * mm, f"YES: {mid.get('quality_yes','')}   NO: {mid.get('quality_no','')}")

    # Section 5
    y5 = y4 - 18 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, y5, "5. Approval Recommendation")
    c.setFont("Helvetica", 10)
    ytxt = y5 - 6 * mm
    ytxt = draw_wrapped_text(c, 20 * mm, ytxt, str(mid.get("approval_recommendation", "")), 170 * mm, 4.2 * mm, max_lines=5)

    # Comments per manager step
    ycom = ytxt - 6 * mm
    c.setFont("Helvetica-Bold", 10)
    c.drawString(20 * mm, ycom, "Comments / Signatures (per workflow):")
    ycom -= 6 * mm
    c.setFont("Helvetica", 9)

    # each step row
    for s in steps[:4]:  # show first 4 similarly to sample
        line = f"Step {s['step_order']} - {s['manager_name']} [{s['action_type']}]  State: {s['latest_state']}  Date: {s['latest_signed_at']}"
        c.drawString(20 * mm, ycom, line)
        ycom -= 4.8 * mm
        if s["latest_notes"]:
            ycom = draw_wrapped_text(c, 24 * mm, ycom, "Notes: " + s["latest_notes"], 160 * mm, 4.0 * mm, max_lines=2)
        ycom -= 2.0 * mm
        if ycom < 20 * mm:
            break

    # Footer
    c.setFont("Helvetica", 8)
    c.drawString(20 * mm, 12 * mm, f"Generated by {APP_NAME} • {now_utc_iso()}")

    c.showPage()
    c.save()
    return buf.getvalue()


def generate_audit_certificate_pdf_bytes(req_row: sqlite3.Row) -> bytes:
    """
    Audit certificate inspired by your report.pdf:
    - Certificate of Fulfilment
    - General Overview
    - Transaction Details
    - Transaction Summary
    - Detailed Audit Trail
    """
    request_id = int(req_row["id"])
    cycle_no = int(req_row["cycle_no"])

    requester = db_query_one("SELECT full_name, email FROM users WHERE id=?", (int(req_row["created_by_user_id"]),))
    steps = get_request_steps(request_id, cycle_no)
    audits = db_query_all(
        "SELECT * FROM audit_log WHERE request_id=? ORDER BY id ASC",
        (request_id,),
    )
    actions = db_query_all(
        """SELECT a.*, u.full_name as manager_name, u.email as manager_email
           FROM request_step_actions a JOIN users u ON u.id=a.manager_id
           WHERE a.request_id=? AND a.cycle_no=?
           ORDER BY a.id ASC""",
        (request_id, cycle_no),
    )

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    # Header
    c.setFont("Helvetica-Bold", 18)
    c.drawString(20 * mm, h - 25 * mm, "Certificate of Fulfilment")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, h - 33 * mm, f"DATE ISSUED: {dt.datetime.now().strftime('%d/%m/%Y %I:%M %p')}")
    c.drawString(20 * mm, h - 39 * mm, f"DOCUMENT ID: {uuid.uuid5(uuid.NAMESPACE_URL, req_row['request_no']).hex}")

    # General Overview box
    y = h - 55 * mm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "General Overview")
    y -= 6 * mm
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y, f"Document name: {req_row['request_no']} - {req_row['request_type']}")
    y -= 5 * mm
    c.drawString(20 * mm, y, f"Status: {compute_status_label(req_row)}")
    y -= 5 * mm
    c.drawString(20 * mm, y, f"Cycle: {cycle_no}")
    y -= 5 * mm
    c.drawString(20 * mm, y, f"Requester: {(requester['full_name'] if requester else '')}")
    y -= 5 * mm
    c.drawString(20 * mm, y, f"Created at: {req_row['created_at']}")
    y -= 8 * mm

    # Transaction Details
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Transaction Details")
    y -= 6 * mm
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, y, f"Signing method: Workflow approvals (Viewer/Signer)")
    y -= 5 * mm
    c.drawString(20 * mm, y, f"Number of participants: {len(steps)}")
    y -= 5 * mm
    sig_count = sum(1 for s in steps if s["action_type"] == "signer")
    c.drawString(20 * mm, y, f"Number of signers: {sig_count}")
    y -= 10 * mm

    # Transaction Summary (actions)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Transaction Summary")
    y -= 6 * mm
    c.setFont("Helvetica", 9)

    for a in actions[-12:]:  # last 12 actions on page 1
        line = f"Step {a['step_order']} - {a['manager_name']} - {a['decision'].upper()} at {a['created_at']}"
        c.drawString(20 * mm, y, line)
        y -= 4.5 * mm
        if a["notes"]:
            y = draw_wrapped_text(c, 24 * mm, y, f"Notes: {a['notes']}", 165 * mm, 4.0 * mm, max_lines=2)
            y -= 1.5 * mm
        if y < 30 * mm:
            break

    # New page: Detailed Audit Trail
    c.showPage()
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20 * mm, h - 20 * mm, "Detailed Audit Trail")
    c.setFont("Helvetica", 9)
    y = h - 30 * mm

    for ev in audits:
        details = safe_json_loads(ev["details"], {})
        line = f"{ev['created_at']} | {ev['action']} | actor={ev['actor_name']} ({ev['actor_role']}) | step={ev['step_order']} | cycle={ev['cycle_no']}"
        c.drawString(20 * mm, y, line)
        y -= 4.3 * mm
        if details:
            dline = json.dumps(details, ensure_ascii=False)
            y = draw_wrapped_text(c, 24 * mm, y, dline, 170 * mm, 4.0 * mm, max_lines=2)
            y -= 1.0 * mm
        if y < 18 * mm:
            c.showPage()
            c.setFont("Helvetica", 9)
            y = h - 20 * mm

    c.setFont("Helvetica", 8)
    c.drawString(20 * mm, 12 * mm, f"Generated by {APP_NAME} • {now_utc_iso()}")

    c.save()
    return buf.getvalue()



#####################################################################################
# Compatibility aliases (template route names)
#####################################################################################

@app.get("/request/<int:request_id>/view")
@login_required
def request_view_alias(request_id: int):
    return redirect(url_for("request_detail", request_id=request_id))


@app.get("/request/<int:request_id>/pdf")
@login_required
def request_form_pdf_alias(request_id: int):
    return redirect(url_for("export_form_pdf", request_id=request_id))


@app.get("/request/<int:request_id>/form.pdf")
@login_required
def request_form_pdf_alias2(request_id: int):
    return redirect(url_for("export_form_pdf", request_id=request_id))


@app.get("/request/<int:request_id>/audit")
@login_required
def request_audit_pdf_alias(request_id: int):
    return redirect(url_for("export_audit_pdf", request_id=request_id))


@app.get("/request/<int:request_id>/audit.pdf")
@login_required
def request_audit_pdf_alias2(request_id: int):
    return redirect(url_for("export_audit_pdf", request_id=request_id))


@app.get("/request/<int:request_id>/export/form.pdf")
@login_required
def export_form_pdf(request_id: int):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)

    # same access rules as request_detail
    user = g.current_user
    is_owner = user.role == ROLE_USER and int(req_row["created_by_user_id"]) == user.id
    is_admin = user.role == ROLE_ADMIN
    is_manager_in_steps = False
    if user.role == ROLE_MANAGER:
        rs = db_query_one(
            "SELECT 1 FROM request_steps WHERE request_id=? AND cycle_no=? AND manager_id=?",
            (request_id, int(req_row["cycle_no"]), user.id),
        )
        is_manager_in_steps = bool(rs)
    if not (is_owner or is_admin or is_manager_in_steps):
        abort(403)

    pdf_bytes = generate_form_pdf_bytes(req_row)
    audit("pdf.export.form", {}, request_id=request_id, cycle_no=int(req_row["cycle_no"]), step_order=int(req_row["current_step_order"]))

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{req_row['request_no']}.pdf",
    )


@app.get("/request/<int:request_id>/export/audit.pdf")
@login_required
def export_audit_pdf(request_id: int):
    req_row = get_request(request_id)
    if not req_row:
        abort(404)

    # same access rules as request_detail
    user = g.current_user
    is_owner = user.role == ROLE_USER and int(req_row["created_by_user_id"]) == user.id
    is_admin = user.role == ROLE_ADMIN
    is_manager_in_steps = False
    if user.role == ROLE_MANAGER:
        rs = db_query_one(
            "SELECT 1 FROM request_steps WHERE request_id=? AND cycle_no=? AND manager_id=?",
            (request_id, int(req_row["cycle_no"]), user.id),
        )
        is_manager_in_steps = bool(rs)
    if not (is_owner or is_admin or is_manager_in_steps):
        abort(403)

    pdf_bytes = generate_audit_certificate_pdf_bytes(req_row)
    audit("pdf.export.audit", {}, request_id=request_id, cycle_no=int(req_row["cycle_no"]), step_order=int(req_row["current_step_order"]))

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{req_row['request_no']}-audit.pdf",
    )


#####################################################################################
# Seeding default users (run once)
#####################################################################################

def seed_defaults() -> None:
    """
    Creates default accounts if DB is empty:
      admin / admin123
      manager1..manager4 / manager123
      user1 / user123
    and default workflow of 4 managers:
      1 signer, 2 signer, 3 viewer, 4 signer (editable).
    """
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON;")

    row = db.execute("SELECT COUNT(1) as c FROM users").fetchone()
    if row and int(row["c"]) > 0:
        db.close()
        return

    ts = now_utc_iso()

    def ins_user(username: str, password: str, full_name: str, role: str, email: str = "") -> int:
        cur = db.execute(
            "INSERT INTO users(username,password_hash,full_name,email,role,is_active,created_at) VALUES(?,?,?,?,?,1,?)",
            (username, generate_password_hash(password), full_name, email, role, ts),
        )
        return int(cur.lastrowid)

    admin_id = ins_user("admin", "admin123", "System Admin", ROLE_ADMIN, "admin@example.com")
    m1 = ins_user("manager1", "manager123", "Manager 1", ROLE_MANAGER, "manager1@example.com")
    m2 = ins_user("manager2", "manager123", "Manager 2", ROLE_MANAGER, "manager2@example.com")
    m3 = ins_user("manager3", "manager123", "Manager 3", ROLE_MANAGER, "manager3@example.com")
    m4 = ins_user("manager4", "manager123", "Manager 4", ROLE_MANAGER, "manager4@example.com")
    u1 = ins_user("user1", "user123", "User 1", ROLE_USER, "user1@example.com")

    # workflow template
    steps = [
        (1, m1, "signer"),
        (2, m2, "signer"),
        (3, m3, "viewer"),
        (4, m4, "signer"),
    ]
    for step_order, manager_id, action_type in steps:
        db.execute(
            "INSERT INTO workflow_template_steps(step_order,manager_id,action_type,is_active,created_at) VALUES(?,?,?,1,?)",
            (step_order, manager_id, action_type, ts),
        )

    db.execute(
        "INSERT INTO audit_log(created_at,actor_id,actor_role,actor_name,request_id,cycle_no,step_order,action,details,ip,user_agent) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (ts, admin_id, ROLE_ADMIN, "System Admin", None, 0, 0, "seed.defaults", json_dumps({"users": 6, "workflow_steps": 4}), "", ""),
    )

    db.commit()
    db.close()


#####################################################################################
# Boot
#####################################################################################

def bootstrap() -> None:
    ensure_scaffold_files()
    init_db()
    seed_defaults()


bootstrap()

if __name__ == "__main__":
    # Run: python app.py
    # Then open: http://127.0.0.1:5000
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
