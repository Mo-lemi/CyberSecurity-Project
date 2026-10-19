import os

from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect


def create_app(test_config=None):
    """Build and configure the Flask app (the "application factory" pattern)."""
    app = Flask(__name__, instance_relative_config=True)

    # Defaults; tests can override any of these through test_config.
    app.config["DATABASE"] = os.path.join(app.instance_path, "securenotes.sqlite")

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

    from . import db

    db.init_app(app)

    # Every POST request must carry a valid CSRF token, or it is rejected
    # with "400 Bad Request" (threat T2). Applied app-wide so no form can be forgotten.
    CSRFProtect(app)

    from . import auth

    app.register_blueprint(auth.bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app
