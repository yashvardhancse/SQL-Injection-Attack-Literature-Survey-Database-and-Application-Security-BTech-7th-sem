# Live Demo Script (≈10 minutes)

A minute-by-minute walkthrough for the presentation. Practise once end-to-end.
Keep the terminal and browser side by side. Reset the DB (`/reset`) before you start.

| Time | You do | You say (key line) |
|------|--------|--------------------|
| 0:00 | Title slide. Introduce team + topic. | "SQL injection is still OWASP Top-10 after 20 years. We show why, and five ways to stop it." |
| 0:45 | `cd prototype && python app.py`; open `http://127.0.0.1:5000`. | "A demo bank login. On the right, a panel shows exactly what SQL runs." |
| 1:30 | **Attack.** Mode = *Vulnerable*, WAF off. Username = `admin' OR '1'='1' -- `, password = `x`. Sign in. | "One line. No password. We're now the admin." (Show dashboard.) |
| 2:30 | Point at the amber banner. | "The quote closes the string, `OR '1'='1'` is always true, `--` comments out the password check." |
| 3:15 | Go back. Switch Mode = *Parameterized*. Replay the **same** payload. | "Same attack. Now the input is a bound parameter, not code." |
| 4:00 | Show the panel: `params = ["admin' OR '1'='1' -- ", "x"]`. | "The database looks for a user literally named `admin' OR...`. There isn't one. Denied." |
| 4:45 | Enable **WAF** checkbox. Replay again. | "Layer zero: a signature firewall spots the tautology and comment and blocks it before the DB." |
| 5:30 | Switch Mode = *Allow-list*. Replay. | "Different idea: only accept characters a real username can have. The quote is rejected instantly." |
| 6:15 | Switch Mode = *ORM*, then *Hashed*. Replay each. | "The ORM parameterizes for us; the hashed variant never even compares plaintext." |
| 7:00 | Log in legitimately: `admin` / `S3cure!Admin` in a protected mode. | "Crucially, real users still log in. Security didn't break usability." |
| 7:45 | Terminal: `python selftest.py`. | "Automated proof: only the vulnerable baseline is bypassed; every defence holds." |
| 8:30 | Results slide. | "Every defence costs under a millisecond. There's no excuse not to use them." |
| 9:00 | Gap → future work slide. | "Even commercial WAFs get bypassed (Qu 2024). Our next layer is adversarially-trained detection." |
| 9:30 | Close. | "Root cause fix + layered defence = defence in depth. Questions?" |

## Backup (if the network / laptop misbehaves)

- Screenshots of every state are in [`figures/`](figures/) — walk through those.
- The zero-install browser demo [`../demo/index.html`](../demo/index.html) needs no
  Python; it runs SQLite in the browser.
- `selftest.py` output is the fastest way to re-prove the whole matrix in one command.

## Pre-flight checklist

- [ ] `pip install -r prototype/requirements.txt` done on the demo laptop.
- [ ] `python app.py` starts and `http://127.0.0.1:5000` loads.
- [ ] DB reset (`/reset`) so `admin` exists and no stale session is logged in.
- [ ] Browser zoom ~125% so the audience can read the SQL panel.
- [ ] Payloads copied to clipboard / sticky note: `admin' OR '1'='1' -- `.
