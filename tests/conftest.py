"""Shared test setup ("fixtures") that pytest makes available to every test file."""

import pytest

from securenotes import create_app
from securenotes.db import init_db

PASSWORD = "correct horse battery"


@pytest.fixture
def app(tmp_path):
    """A fresh app with its own empty database for every test."""
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key",
            "DATABASE": str(tmp_path / "test.sqlite"),
            # CSRF is switched off so tests can post forms directly.
            # The CSRF tests below switch it back on to prove it works.
            "WTF_CSRF_ENABLED": False,
        }
    )
    with app.app_context():
        init_db()
    return app


@pytest.fixture
def client(app):
    """A fake browser that can send requests to the app."""
    return app.test_client()


@pytest.fixture
def make_user(app):
    """Register and log in a user; returns a fake browser logged in as them."""

    def _make_user(username, password=PASSWORD):
        browser = app.test_client()
        browser.post(
            "/auth/register",
            data={"username": username, "password": password, "confirm": password},
        )
        browser.post("/auth/login", data={"username": username, "password": password})
        return browser

    return _make_user
