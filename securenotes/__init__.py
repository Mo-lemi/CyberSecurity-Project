from flask import Flask


def create_app():
    """Build and configure the Flask app (the "application factory" pattern)."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "SecureNotes is running."

    return app
