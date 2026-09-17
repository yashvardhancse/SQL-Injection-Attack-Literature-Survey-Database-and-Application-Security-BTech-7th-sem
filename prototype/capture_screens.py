"""
capture_screens.py -- render real screenshots of the demo for the report/PPT.
Requires the server running on http://127.0.0.1:5000 and Playwright + Chrome.
Run:  python capture_screens.py
Outputs PNGs into ../docs/figures/
"""
import os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:5000"
OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "figures"))
os.makedirs(OUT, exist_ok=True)

INJ = "admin' OR '1'='1' -- "

def shot(page, name):
    page.screenshot(path=os.path.join(OUT, name), full_page=True)
    print("saved", name)

def submit(page, mode, user, pw, waf=False):
    url = f"{BASE}/?mode={mode}" + ("&waf=on" if waf else "")
    page.goto(url, wait_until="networkidle")
    page.fill("input[name=username]", user)
    page.fill("input[name=password]", pw)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1120, "height": 900}, device_scale_factor=2)

    # 1. Clean login page (vulnerable mode)
    page.goto(f"{BASE}/?mode=vulnerable", wait_until="networkidle")
    shot(page, "fig01_login_page.png")

    # 2. Vulnerable mode: injection bypass -> admin dashboard
    submit(page, "vulnerable", INJ, "x")
    shot(page, "fig02_vulnerable_bypass_dashboard.png")

    # 3. Parameterized mode: same payload -> denied, parameterized SQL shown
    submit(page, "parameterized", INJ, "x")
    shot(page, "fig03_parameterized_blocked.png")

    # 4. WAF enabled (vulnerable mode): blocked before DB
    submit(page, "vulnerable", INJ, "x", waf=True)
    shot(page, "fig04_waf_blocked.png")

    # 5. Allow-list mode: rejected by input validation
    submit(page, "allowlist", INJ, "x")
    shot(page, "fig05_allowlist_rejected.png")

    # 6. ORM mode: denied, rendered ORM SQL
    submit(page, "orm", INJ, "x")
    shot(page, "fig06_orm_blocked.png")

    # 7. Legitimate login via hashed variant -> dashboard
    submit(page, "hashed", "admin", "S3cure!Admin")
    shot(page, "fig07_legit_login_hashed.png")

    browser.close()
print("DONE ->", OUT)
