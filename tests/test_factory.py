import pytest

from securenotes import create_app


def test_app_refuses_to_start_without_secret_key(monkeypatch):
    """Threat S3: no secret key means forgeable sessions, so the app must not start."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY is not set"):
        create_app()


def test_session_cookie_is_secure_by_default(monkeypatch):
    """Threat S2: unless .env explicitly says otherwise, cookies are HTTPS-only."""
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    app = create_app({"SECRET_KEY": "x"})
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_debug_is_off_by_default():
    """Threat I5: the interactive debugger must never be on unless asked for."""
    assert not create_app({"SECRET_KEY": "x"}).debug
