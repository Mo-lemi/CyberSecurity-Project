"""Rate limiting tests (threats S1, D1). Limits: 10 per minute per IP address,
5 per minute per username. Different IP addresses are simulated with REMOTE_ADDR."""

import pytest

from securenotes import create_app
from securenotes.db import init_db
from securenotes.limiter import limiter

from .conftest import PASSWORD


@pytest.fixture
def client(tmp_path):
    """A client for an app with rate limiting ON, and all counters reset."""
    app = create_app(
        {
            "SECRET_KEY": "x",
            "DATABASE": str(tmp_path / "limits.sqlite"),
            "SECURITY_LOG": str(tmp_path / "security.log"),
            "WTF_CSRF_ENABLED": False,
        }
    )
    with app.app_context():
        init_db()
        limiter.reset()
    client = app.test_client()
    client.post(
        "/auth/register",
        data={"username": "alice", "password": PASSWORD, "confirm": PASSWORD},
        environ_base={"REMOTE_ADDR": "10.0.0.250"},
    )
    return client


def login(client, username, password="wrong password here", ip="10.0.0.1"):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        environ_base={"REMOTE_ADDR": ip},
    )


def test_one_username_is_limited_even_from_many_ips(client):
    """A botnet guessing ONE person's password (the stalker case, A3)."""
    for attempt in range(5):
        assert login(client, "alice", ip=f"10.0.1.{attempt}").status_code == 200
    assert login(client, "alice", ip="10.0.1.99").status_code == 429


def test_username_limit_ignores_capitals(client):
    for attempt in range(5):
        login(client, "alice", ip=f"10.0.2.{attempt}")
    assert login(client, "ALICE", ip="10.0.2.99").status_code == 429


def test_one_ip_is_limited_even_across_many_usernames(client):
    """One machine trying many accounts (credential stuffing, A4)."""
    for attempt in range(10):
        assert login(client, f"user{attempt}").status_code == 200
    assert login(client, "someone_else").status_code == 429


def test_cooldown_blocks_even_the_right_password(client):
    """Otherwise an attacker could keep guessing and just ignore the 429s."""
    for attempt in range(5):
        login(client, "alice", ip=f"10.0.3.{attempt}")
    assert login(client, "alice", PASSWORD, ip="10.0.3.99").status_code == 429


def test_other_users_are_not_affected(client):
    """A cooldown, not a lockout: limiting alice must not block bob (threat D1)."""
    for attempt in range(5):
        login(client, "alice", ip=f"10.0.4.{attempt}")
    assert login(client, "bob", ip="10.0.4.99").status_code == 200


def test_viewing_the_login_page_is_not_limited(client):
    for _ in range(20):
        assert client.get("/auth/login").status_code == 200


def test_registration_is_limited_per_ip(client):
    for attempt in range(10):
        client.post(
            "/auth/register",
            data={"username": f"new{attempt}", "password": "x", "confirm": "x"},
        )
    response = client.post(
        "/auth/register", data={"username": "one_more", "password": "x", "confirm": "x"}
    )
    assert response.status_code == 429


def test_limit_page_is_friendly_and_keeps_security_headers(client):
    for _ in range(10):
        login(client, "nobody")
    response = login(client, "nobody")
    assert response.status_code == 429
    assert b"Too many attempts" in response.data
    assert response.headers["X-Frame-Options"] == "DENY"
