# SecureNotes

A small note-taking web app built **security-first**: users register, log in, write private notes, and share individual notes with other users. The features are kept deliberately small so the focus stays on threat modelling, secure coding, automated security checks and testing the app's own defences.

> **Status:** 🚧 In development. This README is updated as the project grows.

## Demo

📺 Demo video: _coming soon_

## Features (planned)

- [ ] User registration and login
- [ ] Create, view, edit and delete private notes
- [ ] Share a note with another user (read-only)
- [ ] Rate-limited login to slow down password guessing
- [ ] Runs in Docker

## Security approach

| Activity | What it means here | Status |
|---|---|---|
| **Threat modelling (STRIDE)** | Identify threats to the app *before* writing code, and decide how each one is handled. See [docs/threat-model.md](docs/threat-model.md) | v1 done |
| **OWASP Top 10** | Map each relevant OWASP risk to the defence used in the app | Planned |
| **Secure coding** | Password hashing, CSRF protection, output escaping, parameterised SQL, access checks on every note | Planned |
| **DevSecOps** | GitHub Actions runs tests, a code security scanner (Bandit) and a dependency vulnerability check (pip-audit) on every push | Planned |
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

# 4. Create the database (WARNING: re-running this deletes all data)
flask --app securenotes init-db

# 5. Run the development server
flask --app securenotes run --debug
```

Then open http://127.0.0.1:5000.

> ⚠️ `--debug` is for local development only. Never run with it on a server (see design decision 10).

## Author

Molemi Molokoane

Elective submission verification code: `WTC-KWQHUQ77`
