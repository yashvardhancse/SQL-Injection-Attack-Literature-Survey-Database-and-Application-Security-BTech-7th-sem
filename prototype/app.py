"""
SQL Injection with Protection -- Live Prototype
================================================
A single-file Flask application that demonstrates a SQL-injection-vulnerable
login form and FIVE progressively stronger protection variants, so the same
attack payload can be replayed against each defence and the difference observed
in real time.

Modes (selectable in the UI, sent as ?mode=):
    vulnerable    - string concatenation (INSECURE baseline)
    parameterized - Variant 1: parameterized query (prepared statement)
    allowlist     - Variant 2: input validation (allow-list) + parameterized
    orm           - Variant 3: SQLAlchemy ORM (parameterized by construction)
    hashed        - Variant 4: parameterized + salted password hashing (Werkzeug)
The signature-based WAF (Variant 5) can be toggled ON for ANY mode and inspects
input before the query runs.

Run:
    pip install -r requirements.txt
    python app.py
    # open http://127.0.0.1:5000

Author: DAS PE4 Team -- for authorised educational use only.
"""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, g, redirect, render_template, request, session, url_for
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session
from werkzeug.security import check_password_hash, generate_password_hash

from defenses import (
    WafInspector,
    allowlist_validate,
    build_vulnerable_query,
    timed,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)
app.secret_key = "das-pe4-demo-key-not-for-production"

waf = WafInspector()

MODES = {
    "vulnerable": "Vulnerable (string concatenation)",
    "parameterized": "Variant 1 - Parameterized query",
    "allowlist": "Variant 2 - Input validation (allow-list)",
    "orm": "Variant 3 - ORM (SQLAlchemy)",
    "hashed": "Variant 4 - Parameterized + password hashing",
}


# ---------------------------------------------------------------------------
# Database bootstrap (SQLite). Two credential columns are stored on purpose:
#   password        -> plaintext, representing an INSECURE legacy design
#   password_hash   -> salted PBKDF2 hash used by the secure variants
# Seeding both lets one demo show BOTH the injection and the storage defence.
# ---------------------------------------------------------------------------
SEED_USERS = [
    # username,  password,       role,    email
    ("admin", "S3cure!Admin", "admin", "admin@bank-demo.local"),
    ("alice", "wonderland",   "user",  "alice@bank-demo.local"),
    ("bob",   "builder123",   "user",  "bob@bank-demo.local"),
]


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)          # plaintext (legacy/insecure)
    password_hash = Column(String, nullable=False)     # salted hash (secure)
    role = Column(String, nullable=False)
    email = Column(String, nullable=False)


# SQLAlchemy engine is reused by the ORM variant.
engine = create_engine(f"sqlite:///{DB_PATH}", future=True)


def init_db(force: bool = False) -> None:
    """Create and seed the SQLite database if it does not already exist."""
    if force:
        # Drop then recreate — avoids WinError 32 (can't delete an open file)
        Base.metadata.drop_all(engine)
    fresh = force or not os.path.exists(DB_PATH)
    Base.metadata.create_all(engine)
    if fresh:
        with Session(engine) as s:
            for username, pw, role, email in SEED_USERS:
                s.add(
                    User(
                        username=username,
                        password=pw,
                        password_hash=generate_password_hash(pw),
                        role=role,
                        email=email,
                    )
                )
            s.commit()


def get_conn() -> sqlite3.Connection:
    """Raw sqlite3 connection (used by the concatenation / parameterized paths)."""
    if "conn" not in g:
        g.conn = sqlite3.connect(DB_PATH)
        g.conn.row_factory = sqlite3.Row
    return g.conn


@app.teardown_appcontext
def close_conn(_exc):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


# ---------------------------------------------------------------------------
# Authentication back-ends -- one per mode. Each returns (user_row_or_None).
# ---------------------------------------------------------------------------
@timed
def login_vulnerable(username: str, password: str):
    """INSECURE. Executes attacker-influenced SQL text directly."""
    query = build_vulnerable_query(username, password)
    conn = get_conn()
    try:
        # executescript-free single statement, but the text itself is tainted.
        row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        return {"error": str(exc), "query": query}
    return {"row": row, "query": query}


@timed
def login_parameterized(username: str, password: str):
    """SECURE. User input is bound as data, never parsed as SQL."""
    query = (
        "SELECT id, username, role, email FROM users "
        "WHERE username = ? AND password = ?"
    )
    conn = get_conn()
    row = conn.execute(query, (username, password)).fetchone()
    return {"row": row, "query": query, "params": [username, password]}


@timed
def login_orm(username: str, password: str):
    """SECURE. The ORM builds a parameterized statement from Python objects."""
    with Session(engine) as s:
        stmt = select(User).where(User.username == username, User.password == password)
        user = s.scalars(stmt).first()
        rendered = str(stmt.compile(engine))
    row = None
    if user is not None:
        row = {"id": user.id, "username": user.username, "role": user.role, "email": user.email}
    return {"row": row, "query": rendered}


@timed
def login_hashed(username: str, password: str):
    """SECURE + defence in depth. Parameterized lookup by username only, then a
    constant-time hash verification -- passwords are never stored or compared in
    plaintext."""
    query = "SELECT id, username, role, email, password_hash FROM users WHERE username = ?"
    conn = get_conn()
    row = conn.execute(query, (username,)).fetchone()
    if row is None:
        return {"row": None, "query": query, "params": [username]}
    if check_password_hash(row["password_hash"], password):
        return {"row": row, "query": query, "params": [username]}
    return {"row": None, "query": query, "params": [username], "reason": "password hash mismatch"}


def normalize_row(row):
    """Turn a sqlite3.Row / dict into a plain dict for the template."""
    if row is None:
        return None
    if isinstance(row, dict):
        return {k: row[k] for k in ("id", "username", "role", "email") if k in row}
    return {"id": row["id"], "username": row["username"], "role": row["role"], "email": row["email"]}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    mode = request.values.get("mode", "vulnerable")
    if mode not in MODES:
        mode = "vulnerable"
    waf_enabled = request.values.get("waf") == "on"

    context = {
        "modes": MODES,
        "mode": mode,
        "waf_enabled": waf_enabled,
        "result": None,
    }

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        result = {
            "username": username,
            "password": password,
            "waf": None,
            "blocked": False,
        }

        # --- Variant 5: WAF pre-filter (optional, works for every mode) -------
        if waf_enabled:
            verdict = waf.inspect(username, password)
            result["waf"] = verdict.summary
            if verdict.blocked:
                result["blocked"] = True
                result["outcome"] = "denied"
                result["message"] = "Request blocked by WAF before reaching the database."
                context["result"] = result
                return render_template("login.html", **context)

        # --- Variant 2: allow-list validation --------------------------------
        if mode == "allowlist":
            ok, reason = allowlist_validate(username, password)
            result["validation"] = reason
            if not ok:
                result["outcome"] = "denied"
                result["message"] = "Rejected by input validation."
                context["result"] = result
                return render_template("login.html", **context)

        # --- dispatch to the selected back-end -------------------------------
        backend = {
            "vulnerable": login_vulnerable,
            "parameterized": login_parameterized,
            "allowlist": login_parameterized,  # allow-list runs on top of parameterization
            "orm": login_orm,
            "hashed": login_hashed,
        }[mode]

        payload, elapsed_ms = backend(username, password)
        result["elapsed_ms"] = round(elapsed_ms, 2)
        result["query"] = payload.get("query")
        result["params"] = payload.get("params")
        if payload.get("error"):
            result["outcome"] = "error"
            result["message"] = f"Database error: {payload['error']}"
        else:
            user = normalize_row(payload.get("row"))
            if user:
                session["user"] = user
                session["via_mode"] = MODES[mode]
                return redirect(url_for("dashboard"))
            result["outcome"] = "failed"
            result["message"] = "Invalid credentials. Login denied."
        context["result"] = result

    return render_template("login.html", **context)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html", user=session["user"], via_mode=session.get("via_mode", "")
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/reset")
def reset():
    """Rebuild the demo database (handy between presentation runs)."""
    init_db(force=True)
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
