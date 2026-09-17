"""
defenses.py
===========
Protection primitives for the SQL-injection demonstrator.

Each function isolates ONE defensive technique so the accompanying report and
presentation can point to a single, auditable code path per variant:

    1. build_vulnerable_query   -> the insecure baseline (string concatenation)
    2. parameterized_login      -> Variant 1: parameterized / prepared statements
    3. allowlist_validate       -> Variant 2: input validation (allow-list)
    4. WafInspector             -> Variant 3: signature/heuristic WAF layer
    (ORM and hashed-credential variants live in app.py because they need the
     SQLAlchemy session / Werkzeug hasher.)

The design deliberately mirrors the "defence-in-depth" framing used in the
literature survey: no single control is treated as sufficient on its own.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Insecure baseline
# ---------------------------------------------------------------------------
def build_vulnerable_query(username: str, password: str) -> str:
    """Reproduce the classic anti-pattern: untrusted input concatenated
    directly into SQL text. Returned so the UI can *show* the tampered query.

    Example: username = admin' --   ->   ... WHERE username='admin' --' ...
    """
    return (
        "SELECT id, username, role, email FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )


# ---------------------------------------------------------------------------
# Variant 2: Input validation via allow-list
# ---------------------------------------------------------------------------
# An allow-list is safer than a block-list: instead of guessing every malicious
# pattern, we accept only characters known to be legitimate for the field.
USERNAME_ALLOWLIST = re.compile(r"^[A-Za-z0-9_.@\-]{1,32}$")
PASSWORD_MAXLEN = 128


def allowlist_validate(username: str, password: str) -> tuple[bool, str]:
    """Return (is_valid, reason). Rejects anything outside the expected shape
    of a username, and over-long passwords, before a query is ever built."""
    if not username or not password:
        return False, "Empty username or password."
    if len(password) > PASSWORD_MAXLEN:
        return False, "Password exceeds maximum allowed length."
    if not USERNAME_ALLOWLIST.match(username):
        return False, (
            "Username contains characters outside the allow-list "
            "[A-Za-z0-9_.@-]. Request rejected before it reached the database."
        )
    return True, "Input conforms to the allow-list."


# ---------------------------------------------------------------------------
# Variant 3: lightweight signature / heuristic WAF
# ---------------------------------------------------------------------------
# Inspired by the OWASP Core Rule Set and the WAF studies in the survey
# (Alotaibi & Vassilakis, 2023; Floris et al., 2025). This is intentionally a
# *transparent, readable* rule set for teaching -- production WAFs are far
# larger and, as the survey notes, still bypassable by adversarial payloads.
_WAF_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("tautology (OR/AND 1=1)", re.compile(r"\b(or|and)\b\s+[\w'\"]+\s*=\s*[\w'\"]+", re.I)),
    ("inline / terminating comment", re.compile(r"(--|#|/\*|\*/)")),
    ("stacked query", re.compile(r";\s*\w")),
    ("UNION-based", re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.I)),
    ("SQL keyword in credential", re.compile(r"\b(select|insert|update|delete|drop|exec|xp_)\b", re.I)),
    ("quote breakout", re.compile(r"['\"]\s*(or|and|;|--|\))", re.I)),
    ("time-based blind (SLEEP/WAITFOR)", re.compile(r"\b(sleep|waitfor|benchmark|pg_sleep)\b", re.I)),
]


@dataclass
class WafVerdict:
    blocked: bool
    hits: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.blocked:
            return "No signatures matched."
        return "Blocked. Matched rules: " + "; ".join(self.hits)


class WafInspector:
    """Signature-based request inspector. Call `inspect()` on each raw field."""

    def inspect(self, *fields: str) -> WafVerdict:
        hits: list[str] = []
        blob = " ".join(f for f in fields if f)
        for name, pattern in _WAF_SIGNATURES:
            if pattern.search(blob):
                hits.append(name)
        return WafVerdict(blocked=bool(hits), hits=hits)


# ---------------------------------------------------------------------------
# Small helper: consistent-ish timing so the UI can display query latency
# ---------------------------------------------------------------------------
def timed(fn):
    """Decorator that returns (result, elapsed_ms)."""

    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return result, elapsed_ms

    return wrapper
