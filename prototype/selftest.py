"""
selftest.py -- automated evidence that the defences work.

Replays the same injection payload against every mode and prints a table of
outcomes. Also verifies that legitimate credentials still authenticate.
Run:  python selftest.py
"""
from __future__ import annotations

import app as demo

INJECTION_USER = "admin' OR '1'='1' -- "
INJECTION_PW = "x"
LEGIT_USER, LEGIT_PW = "admin", "S3cure!Admin"

MODES = ["vulnerable", "parameterized", "allowlist", "orm", "hashed"]


def attempt(client, mode, user, pw, waf=False):
    url = f"/?mode={mode}" + ("&waf=on" if waf else "")
    r = client.post(url, data={"username": user, "password": pw}, follow_redirects=False)
    # 302 redirect => login succeeded (redirect to /dashboard)
    return r.status_code == 302


def main():
    demo.init_db(force=True)
    demo.app.testing = True
    client = demo.app.test_client()

    print("=" * 72)
    print("INJECTION PAYLOAD:", repr(INJECTION_USER))
    print("=" * 72)
    print(f"{'mode':<16}{'WAF off: bypass?':<20}{'WAF on: bypass?':<18}")
    print("-" * 72)
    for mode in MODES:
        off = attempt(client, mode, INJECTION_USER, INJECTION_PW, waf=False)
        on = attempt(client, mode, INJECTION_USER, INJECTION_PW, waf=True)
        print(f"{mode:<16}{('YES (bypassed!)' if off else 'no'):<20}{('YES' if on else 'no'):<18}")

    print("-" * 72)
    print("Legitimate login still works (each secure mode):")
    for mode in ["parameterized", "allowlist", "orm", "hashed"]:
        ok = attempt(client, mode, LEGIT_USER, LEGIT_PW, waf=True)
        print(f"  {mode:<16}-> {'OK' if ok else 'FAILED (regression!)'}")

    print("=" * 72)
    print("Expected: only 'vulnerable' with WAF off shows YES; all secure modes 'no';")
    print("legitimate logins all OK.")


if __name__ == "__main__":
    main()
