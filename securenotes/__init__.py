import os

from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect


def create_app(test_config=None):
    """Build and configure the Flask app (the "application factory" pattern)."""
    app = Flask(__name__, instance_relative_config=True)

    # Defaults; tests can override any of these through test_config.
    app.config["DATABASE"] = os.path.join(app.instance_path, "securenotes.sqlite")

    # Reject any request body over 256 KB with "413 Request Entity Too Large" (threat D2).
    # Plenty for a 10,000-character note, even with emoji and form encoding.
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

    # Rate limiting is on unless a config explicitly turns it off. Set here on
    # purpose: otherwise Flask-Limiter can inherit "off" from a previous app.
    app.config["RATELIMIT_ENABLED"] = True

    # Session cookie hardening (threat S2):
    # HttpOnly - JavaScript can't read the cookie, so an XSS bug can't steal it.
    # SameSite=Lax - the browser won't attach it to forms submitted from other sites.
    # Secure - only sent over HTTPS. On by default; .env turns it off for local http.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false"
    )

    if test_config is None:
        # Normal run: the secret comes from the environment (.env), never from code.
        app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
    else:
        # Tests pass in their own settings instead.
        app.config.from_mapping(test_config)

    # Fail fast: without a secret key, session cookies could be forged (threat S3).
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY is not set. Copy .env.example to .env and add a random key."
        )

    # The instance folder holds local-only files like the database (git-ignored).
    os.makedirs(app.instance_path, exist_ok=True)

    from . import audit, db, headers, limiter

    db.init_app(app)
    audit.init_app(app)
    headers.init_app(app)
    limiter.init_app(app)

    # Every POST request must carry a valid CSRF token, or it is rejected
    # with "400 Bad Request" (threat T2). Applied app-wide so no form can be forgotten.
    CSRFProtect(app)

    from . import auth, notes

    app.register_blueprint(auth.bp)
    app.register_blueprint(notes.bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app
