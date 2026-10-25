# SecureNotes

[![CI](https://github.com/Mo-lemi/CyberSecurity-Project/actions/workflows/ci.yml/badge.svg)](https://github.com/Mo-lemi/CyberSecurity-Project/actions/workflows/ci.yml)

A small note-taking web app built **security-first**: users register, log in, write private notes, and share individual notes with other users. The features are kept deliberately small so the focus stays on threat modelling, secure coding, automated security checks and testing the app's own defences.

> **Status:** 🚧 In development. This README is updated as the project grows.

## Demo

📺 Demo video: _coming soon_

## Features (planned)

- [x] User registration and login
- [x] Create, view, edit and delete private notes
- [x] Share a note with another user (read-only)
- [ ] Rate-limited login to slow down password guessing
- [ ] Runs in Docker

## Security approach

| Activity | What it means here | Status |
|---|---|---|
| **Threat modelling (STRIDE)** | Identify threats to the app *before* writing code, and decide how each one is handled. See [docs/threat-model.md](docs/threat-model.md) | v1 done |
| **OWASP Top 10** | Map each relevant OWASP risk to the defence used in the app | Planned |
| **Secure coding** | Password hashing, CSRF protection, output escaping, parameterised SQL, access checks on every note, security headers | Done; sharing and rate limiting next |
| **DevSecOps** | GitHub Actions runs tests, a code security scanner (Bandit) and a dependency vulnerability check (pip-audit) on every push. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Done |
| **Self-pentest** | Attack the finished app with Burp Suite and ffuf, then write up and fix the findings | Planned |

## Tech stack

- **Python 3.13** with **Flask**
- **Jinja2** server-rendered HTML templates
- **SQLite** database
- **argon2** password hashing
- **Flask-WTF** for CSRF tokens
- **Docker** and **GitHub Actions**

## Design decisions

Decisions are recorded as they are made, with the reasoning behind them.

1. **Small feature set, deep security.** A notes app with sharing is small enough to finish and explain fully, but it still exercises the core web security problems: authentication, sessions, access control, injection and cross-site attacks.
2. **Sharing is included on purpose.** Sharing means some users may read a note and others may not. That creates the classic *Insecure Direct Object Reference* (IDOR) risk, where changing a note ID in the URL could expose someone else's note. Designing and testing that access check is a central part of the project.
3. **Flask with server-rendered pages instead of a separate JavaScript frontend.** This means fewer moving parts and less code that could hide bugs. Jinja2 escapes output automatically, which defends against cross-site scripting (XSS), and there is no API, CORS or token handling to secure.
4. **SQLite.** A single-file database with no server to configure or expose. All queries will use parameters, never string concatenation, to prevent SQL injection.
5. **argon2 for passwords.** Passwords are never stored, only slow, salted hashes. Argon2 is the algorithm currently recommended by OWASP for password storage.
6. **Threat model before code.** Writing the STRIDE threat model first means the security controls are designed in from the start rather than added afterwards.
7. **Pinned dependency versions.** `requirements.txt` lists exact versions (e.g. `Flask==3.1.3`), so every install gets the same code. A new release can't silently change the app's behaviour, and pip-audit can check those exact versions against known vulnerabilities. Dependencies are added only when a feature needs them.
8. **Secrets and databases stay out of Git.** `.gitignore` excludes `.env` files, the `instance/` folder and database files. Anything pushed to a public repo should be treated as exposed forever, even if it is deleted later.
9. **Application factory (`create_app()`).** The app is built inside a function instead of at import time. Tests can create a fresh app with test settings (e.g. a temporary database), and nothing is configured until it is needed.
10. **Debug mode only on localhost.** Flask's debug mode shows an interactive debugger in the browser when an error occurs, which lets anyone who can reach the page run Python code on the server. It is only used locally, and the dev server listens on `127.0.0.1`, so other machines can't reach it.
11. **`SECRET_KEY` from the environment, and the app refuses to start without it.** Flask signs session cookies with this key, so anyone who knows it can forge a login as any user (threat S3). It lives in a git-ignored `.env` file, with a committed `.env.example` showing the format. There is deliberately **no fallback default** like `"dev"`: a default would be public in the repo, and the app could silently run with it in production.
12. **Usernames instead of email addresses.** The app never sends email (there is no password reset, see the [threat model](docs/threat-model.md)), so collecting emails would only mean storing personal data it doesn't need. If the database ever leaked, usernames reveal far less about real people. Usernames are case-insensitive (`COLLATE NOCASE`), so nobody can register `Alice` to impersonate `alice`.
13. **One database connection per request.** `get_db()` opens a connection the first time a request needs it and `close_db()` always closes it when the request ends, so connections never leak or get shared between users' requests. Foreign keys are switched on for every connection, because SQLite ignores them by default.
14. **CSRF protection is switched on for the whole app, not per form.** `CSRFProtect` rejects *every* POST request that lacks a valid token, so a new form can't accidentally be left unprotected. It was added *before* the first form existed, so no form was ever unprotected (threat T2).
15. **No inline CSS or JavaScript.** All styling lives in `static/style.css`. That makes it possible to add a strict Content-Security-Policy later that blocks inline scripts, a second layer of defence against XSS (threat I3).
16. **argon2id with the library's default settings.** `argon2-cffi`'s defaults follow RFC 9106 (64 MiB of memory, 3 passes), which makes each guess slow and memory-hungry for an attacker with a stolen database. Each hash includes its own random salt, so two users with the same password get different hashes. Passwords must be 12–128 characters: long enough to resist guessing, and capped so nobody can send a huge password to slow the server down.
17. **Duplicate usernames are caught by the database, not by checking first.** Running `SELECT` and then `INSERT` leaves a gap where two people could register the same name at once. Instead, the `UNIQUE` constraint rejects the duplicate and the app catches the error. The database is the single source of truth.
18. **"Username taken" is an accepted risk.** Registration has to tell people a name is in use, which also reveals that the account exists (user enumeration). The login page will still give one generic error, and rate limiting will slow down bulk checking. This is recorded under threat S5.
19. **One vague login error, and equal timing.** Login always says "Invalid username or password", never *which* one was wrong. Checking an argon2 hash takes about 70 ms, so skipping the check for unknown usernames would make them respond noticeably faster, and an attacker could time the responses to find real accounts. Unknown usernames are therefore checked against a dummy hash, so both cases take the same time.
20. **Hardened session cookie.** `HttpOnly` (JavaScript can't read it, so XSS can't steal it), `SameSite=Lax` (not sent with forms from other sites) and `Secure` (HTTPS only). `Secure` is **on by default** and can only be turned off explicitly in `.env` for local development. If the setting is forgotten, the app fails safe: logins stop working over plain http rather than cookies leaking.
21. **The session is cleared on login and logout.** Nothing stored in the session before login carries over afterwards (session fixation, threat S4).
22. **Logout is a POST request.** If logout were a plain link (GET), any website could log users out by embedding `<img src=".../auth/logout">`. As a POST, it requires a CSRF token.
23. **A note's owner always comes from the session, never from the form.** When a note is created, `owner_id` is taken from the logged-in user (`g.user`). Even if an attacker adds an `owner_id` field to the request with Burp Suite, it is ignored, so nobody can create notes "as" someone else.
24. **`login_required` as a decorator.** Pages that need a login are marked with `@login_required`, which redirects logged-out visitors to the login page. One shared check is harder to forget or get wrong than repeating an `if` in every page.
25. **Two layers of size limits.** Notes are capped at 100 characters for the title and 10,000 for the body, with a friendly error message. Separately, Flask rejects any request over 256 KB before the app even reads it, which protects every page, not just notes (threat D2).
26. **The owner check is built into the database query.** Every page that opens a note goes through one helper, `get_owned_note()`, which runs `... WHERE id = ? AND owner_id = ?`. A note simply can't be loaded without the ownership check, so there is no separate `if` that a future change could forget. `UPDATE` and `DELETE` repeat `AND owner_id = ?` as a second layer (defence in depth).
27. **"Not yours" looks exactly like "doesn't exist".** Both return the same 404 page. A 403 Forbidden would confirm that note 42 *exists*, which tells an attacker (or a stalker, threat A3) that there is something worth targeting.
28. **Note IDs are plain numbers on purpose.** Random IDs would make guessing harder, but that is security through obscurity. The access check is the real defence, and sequential IDs make it easy to *prove* it works: changing `/notes/1` to `/notes/2` in Burp Suite should always fail.
29. **Separate `requirements-dev.txt` for test tools.** pytest is needed to *develop* the app, not to *run* it. Keeping it out of `requirements.txt` means the production install (and later the Docker image) contains less code, and so less that could be vulnerable.
30. **Tests are written against the threat model.** Each security test names the threat it covers (e.g. *"Threat I2: a 403 would confirm the note exists"*), so the threat model's 🔍 *verified* status points to real evidence. To check the tests themselves, the owner check was deliberately removed once: 5 access-control tests failed, proving they catch an IDOR bug.
31. **The CI pipeline has read-only permissions.** The GitHub Actions workflow is given `contents: read` and nothing else (least privilege). If a tool running in CI were ever compromised, it couldn't push code or change the repository.
32. **CI actions are pinned to exact commits.** Third-party actions are referenced by commit hash (e.g. `actions/checkout@3d3c42e...`) rather than a tag like `v7`. A tag can be moved to point at different code, as happened in the 2025 `tj-actions/changed-files` supply-chain attack, but a commit hash can't (threat T4).
33. **Security scans block the build.** Bandit (static analysis of our own code) and pip-audit (known vulnerabilities in dependencies) run in their own CI job. Any finding fails the build with a red ❌, instead of producing a report nobody reads. Bandit scans only `securenotes/`, not `tests/`, because tests use `assert` on purpose and Bandit would flag every one.
34. **A Content-Security-Policy that allows no scripts at all.** SecureNotes has no JavaScript, so the policy (`default-src 'none'`) blocks scripts completely instead of listing allowed ones. If an XSS bug ever slipped past Jinja2's escaping, the browser would still refuse to run the injected script. That's two independent layers for threat I3. `frame-ancestors 'none'` and `X-Frame-Options: DENY` stop other sites loading SecureNotes in a hidden frame (clickjacking, I7).
35. **Private pages are never cached.** `Cache-Control: no-store` stops the browser keeping copies of pages, so on a shared computer the next person can't press Back after logout and read someone's notes (threat I8, found while adding these headers). The stylesheet is excluded because it contains nothing private.
36. **No HSTS header yet.** `Strict-Transport-Security` forces browsers to always use HTTPS, but it only makes sense once the app is deployed with HTTPS. Sent from `http://127.0.0.1` it would be ignored, and on a misconfigured server it could lock users out. It belongs in the deployment configuration.
37. **Sharing is owner-only, using the same gatekeeper.** Share and revoke both start with `get_owned_note()`, the same check used by edit and delete. Anyone who isn't the owner, including people the note is shared with, gets a 404 (threat E1). Shares live in their own table, whose primary key `(note_id, user_id)` makes duplicate shares impossible, and they are deleted automatically when the note is.
38. **Sharing with an unknown username says so.** "No user with that name" reveals that a username doesn't exist. Registration already reveals the same thing, so hiding it here would protect nothing and would make typos look like successful shares. Same accepted risk as decision 18 (threat S5).
39. **Only the owner sees who has access.** Alice sees the list of people she shared with and can remove each one. People she shares with don't see each other, so sharing with Bob never reveals Carol's username to him.
40. **Two gatekeepers: one for reading, one for changing.** `get_readable_note()` lets in the owner *or* someone the note is shared with, and it is used **only** to view a note. Everything that changes a note (edit, delete, share, revoke) uses the stricter `get_owned_note()`. Hiding the Edit and Delete buttons from readers is just for a clean page; the server-side check is what actually stops a reader who sends those requests by hand. To test the tests, `edit` was deliberately switched to the looser check, and 2 tests failed immediately.

## Roadmap

- **Week 1:** README, project structure, minimal Flask app, STRIDE threat model v1
- **Week 2:** Registration and login, CSRF protection, notes with owner checks, tests
- **Week 3:** Note sharing, login rate limiting, security headers, Docker, CI security pipeline
- **Week 4:** Self-pentest with Burp Suite and ffuf, findings report, OWASP Top 10 mapping, demo video

## Running locally

Requires Python 3.13+. Commands below are for Windows PowerShell.

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create your local .env with a random secret key
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
# ...then paste the printed value into .env as SECRET_KEY=<value>
# and keep SESSION_COOKIE_SECURE=false (local http only)

# 4. Create the database (WARNING: re-running this deletes all data)
python -m flask --app securenotes init-db

# 5. Run the development server
python -m flask --app securenotes run --debug
```

Then open http://127.0.0.1:5000.

> ⚠️ `--debug` is for local development only. Never run with it on a server (see design decision 10).

## Running the tests

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Every test gets a fresh, empty database in a temporary folder, so tests never touch your real data. The access-control (IDOR) tests are in [`tests/test_notes.py`](tests/test_notes.py).

The same tests run automatically on GitHub Actions for every push (see the CI badge at the top).

## Author

Molemi Molokoane

Elective submission verification code: `WTC-KWQHUQ77`
