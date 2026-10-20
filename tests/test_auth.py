import pytest

from securenotes import create_app
from securenotes.auth import LOGIN_ERROR
from securenotes.db import get_db

from .conftest import PASSWORD


def register(client, username, password=PASSWORD, confirm=None):
    return client.post(
        "/auth/register",
        data={
            "username": username,
            "password": password,
            "confirm": password if confirm is None else confirm,
        },
        follow_redirects=True,
    )


# --- Registration -----------------------------------------------------------


def test_register_creates_user_and_redirects_to_login(client):
    response = client.post(
        "/auth/register",
        data={"username": "alice", "password": PASSWORD, "confirm": PASSWORD},
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/login"


def test_password_is_stored_as_argon2_hash_not_plaintext(app, client):
    """Threat I4: a stolen database must not reveal passwords."""
    register(client, "alice")
    with app.app_context():
        stored = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_same_password_gives_different_hashes(app, client):
    """Each hash has its own random salt."""
    register(client, "alice")
    register(client, "bob")
    with app.app_context():
        hashes = [row[0] for row in get_db().execute("SELECT password_hash FROM users")]
    assert hashes[0] != hashes[1]


def test_duplicate_username_is_rejected_ignoring_case(client):
    register(client, "alice")
    response = register(client, "ALICE")
    assert b"That username is already taken." in response.data


@pytest.mark.parametrize(
    ("username", "password", "confirm", "message"),
    [
        ("ab", PASSWORD, None, b"Username must be 3"),
        ("<script>", PASSWORD, None, b"Username must be 3"),
        ("x' OR 1=1--", PASSWORD, None, b"Username must be 3"),
        ("alice", "short", None, b"Password must be 12"),
        ("alice", "x" * 129, None, b"Password must be 12"),
        ("alice", PASSWORD, "something else", b"Passwords do not match."),
    ],
)
def test_register_rejects_invalid_input(client, username, password, confirm, message):
    response = register(client, username, password, confirm)
    assert message in response.data


# --- Login and logout -------------------------------------------------------


def test_login_success_sets_hardened_session_cookie(client):
    register(client, "alice")
    response = client.post("/auth/login", data={"username": "alice", "password": PASSWORD})
    assert response.status_code == 302
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_logged_in_user_is_shown_in_nav(make_user):
    browser = make_user("alice")
    assert b"Signed in as <strong>alice</strong>" in browser.get("/").data


@pytest.mark.parametrize(
    ("username", "password"),
    [("alice", "wrong password here"), ("nobody", PASSWORD)],
)
def test_login_failure_gives_one_generic_message(client, username, password):
    """Threat S5: wrong username and wrong password must look identical."""
    register(client, "alice")
    response = client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert LOGIN_ERROR.encode() in response.data
    assert b"Signed in as" not in response.data


def test_logout_must_be_post(make_user):
    """A GET logout could be triggered by an <img> tag on any website."""
    browser = make_user("alice")
    assert browser.get("/auth/logout").status_code == 405


def test_logout_clears_session(make_user):
    browser = make_user("alice")
    browser.post("/auth/logout")
    assert b"Signed in as" not in browser.get("/").data


# --- CSRF (threat T2) -------------------------------------------------------


@pytest.fixture
def csrf_client(tmp_path):
    """A client for an app with CSRF protection switched ON, as in real use."""
    app = create_app({"SECRET_KEY": "x", "DATABASE": str(tmp_path / "csrf.sqlite")})
    return app.test_client()


@pytest.mark.parametrize("url", ["/auth/register", "/auth/login", "/auth/logout"])
def test_forms_without_csrf_token_are_rejected(csrf_client, url):
    assert csrf_client.post(url, data={"username": "alice"}).status_code == 400
