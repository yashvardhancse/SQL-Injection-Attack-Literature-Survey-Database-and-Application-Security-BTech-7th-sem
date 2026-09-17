# Prototype — SQLi Defence Lab (Flask + SQLite)

A vulnerable login and **five protection variants** behind one UI, so the same
payload can be replayed against each defence.

## Run

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

`app.py` seeds `users.db` automatically on first run. Visit `/reset` any time to
rebuild a clean database between demo runs.

## Files

| File | Purpose |
|------|---------|
| `app.py` | Flask app; one login route dispatches to five back-ends |
| `defenses.py` | Isolated protection primitives (allow-list, WAF signatures, vulnerable query builder) |
| `templates/` | `login.html`, `dashboard.html`, `base.html` |
| `static/style.css` | Dark UI theme |
| `selftest.py` | Automated proof: replays the attack against every mode |
| `capture_screens.py` | Playwright script that regenerates the screenshots |

## Seeded accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `S3cure!Admin` | admin |
| `alice` | `wonderland` | user |
| `bob` | `builder123` | user |

## Modes (dropdown on the login page)

| Mode | Behaviour |
|------|-----------|
| `vulnerable` | String concatenation — **insecure baseline** |
| `parameterized` | Bound parameters — injection treated as data |
| `allowlist` | Regex allow-list rejects bad input, then parameterized |
| `orm` | SQLAlchemy ORM — parameterized by construction |
| `hashed` | Parameterized lookup + salted PBKDF2 verification |

The **signature WAF** checkbox (Variant 5) can be enabled for *any* mode; it
inspects input and blocks known attack patterns before the database is touched.

## Try it

Paste into the **Username** field (password = anything):

```text
' OR '1'='1' -- 
admin' -- 
admin' OR 1=1 -- 
' UNION SELECT id,username,role,email FROM users -- 
```

- **Vulnerable mode:** you land on the `admin` dashboard with no valid password.
- **Any protected mode / WAF on:** the identical payload is rejected, and the
  "What is happening" panel shows the exact SQL and (for parameterized modes) the
  bound parameters proving the input was treated as data.

## Verify automatically

```bash
python selftest.py
```

Only `vulnerable` (WAF off) should report a bypass; every protected mode blocks
the attack while legitimate logins keep working.

## Regenerate screenshots (optional)

```bash
python _serve.py &        # start server (no reloader)
python capture_screens.py # needs Playwright + Chrome; writes to ../docs/figures/
```

> Authorised educational use only. All attacks target the bundled local database.
