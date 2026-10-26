"""Rate limiting (threats S1, D1, and slowing bulk username checks for S5).

Limits are counted in memory: simple, with nothing extra to run, but the counts
reset when the app restarts and only work with a single server process. A real
multi-server deployment would point storage_uri at a shared store such as Redis.
"""

from flask import render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Counts requests per IP address by default.
# get_remote_address uses the address that actually connected; it deliberately
# ignores the X-Forwarded-For header, which any client can fake.
limiter = Limiter(get_remote_address, storage_uri="memory://")

# Per IP: stops one machine trying many accounts (credential stuffing, A4).
PER_IP = "10 per minute"
# Per username: stops many machines slowly guessing ONE person's password (A3).
PER_USERNAME = "5 per minute"


def username_key():
    """Rate-limit key for the username typed into the form ("Alice" == "alice")."""
    return "user:" + request.form.get("username", "").strip().lower()


def too_many_requests(error):
    return render_template("errors/429.html"), 429


def init_app(app):
    limiter.init_app(app)
    app.register_error_handler(429, too_many_requests)
