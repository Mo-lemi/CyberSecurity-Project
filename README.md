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
| **Threat modelling (STRIDE)** | Identify threats to the app *before* writing code, and decide how each one is handled | Planned |
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

## Roadmap

- **Week 1:** README, project structure, minimal Flask app, STRIDE threat model v1
- **Week 2:** Registration and login, CSRF protection, notes with owner checks, tests
- **Week 3:** Note sharing, login rate limiting, security headers, Docker, CI security pipeline
- **Week 4:** Self-pentest with Burp Suite and ffuf, findings report, OWASP Top 10 mapping, demo video

## Running locally

_Instructions will be added once the first version of the app runs._

## Author

Molemi Molokoane
