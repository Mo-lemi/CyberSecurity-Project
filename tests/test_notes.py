"""Notes tests. The access-control tests here are the most important in the project:
they prove one user can never read, change or delete another user's notes."""

import pytest

from securenotes.db import get_db


@pytest.fixture
def alice(make_user):
    browser = make_user("alice")
    browser.post(
        "/notes/new", data={"title": "Birthday party", "body": "12 Main St, Sat 7pm"}
    )
    return browser  # Alice owns note 1


@pytest.fixture
def bob(make_user):
    return make_user("bob")


def note_1(app):
    with app.app_context():
        return get_db().execute("SELECT title, body FROM notes WHERE id = 1").fetchone()


# --- Login required (threat E2) ----------------------------------------------


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("get", "/notes/"),
        ("get", "/notes/new"),
        ("post", "/notes/new"),
        ("get", "/notes/1"),
        ("get", "/notes/1/edit"),
        ("post", "/notes/1/edit"),
        ("post", "/notes/1/delete"),
    ],
)
def test_logged_out_visitors_are_sent_to_login(client, method, url):
    response = getattr(client, method)(url)
    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/login"


# --- The owner's own notes --------------------------------------------------


def test_owner_can_create_view_edit_and_delete(alice):
    assert b"Birthday party" in alice.get("/notes/").data
    assert b"12 Main St" in alice.get("/notes/1").data

    alice.post("/notes/1/edit", data={"title": "Party (moved)", "body": "New address"})
    assert b"Party (moved)" in alice.get("/notes/1").data

    alice.post("/notes/1/delete")
    assert alice.get("/notes/1").status_code == 404


def test_delete_must_be_post(alice):
    assert alice.get("/notes/1/delete").status_code == 405


# --- Access control: IDOR (threats I1, I2, T1) -------------------------------


def test_other_users_notes_are_not_listed(alice, bob):
    assert b"Birthday party" not in bob.get("/notes/").data


@pytest.mark.parametrize(
    ("method", "url", "data"),
    [
        ("get", "/notes/1", None),
        ("get", "/notes/1/edit", None),
        ("post", "/notes/1/edit", {"title": "HACKED", "body": "x"}),
        ("post", "/notes/1/delete", None),
    ],
)
def test_user_cannot_touch_another_users_note(app, alice, bob, method, url, data):
    response = getattr(bob, method)(url, data=data)
    assert response.status_code == 404
    # ...and Alice's note is unchanged.
    assert tuple(note_1(app)) == ("Birthday party", "12 Main St, Sat 7pm")


def test_someone_elses_note_looks_exactly_like_a_missing_note(alice, bob):
    """Threat I2: a 403 would confirm the note exists, so both must be identical."""
    not_yours = bob.get("/notes/1")
    missing = bob.get("/notes/999")
    assert not_yours.status_code == missing.status_code == 404
    assert not_yours.data == missing.data


def test_owner_id_in_form_is_ignored(app, bob):
    """Design decision 23: the owner always comes from the session."""
    bob.post("/notes/new", data={"title": "Sneaky", "body": "", "owner_id": "1"})
    with app.app_context():
        owner = get_db().execute(
            "SELECT users.username FROM notes JOIN users ON users.id = notes.owner_id"
        ).fetchone()[0]
    assert owner == "bob"


# --- Input handling ----------------------------------------------------------


def test_note_content_is_html_escaped(alice):
    """Threat I3: a script in a note must be shown as text, never run."""
    alice.post("/notes/new", data={"title": "<script>alert(1)</script>", "body": ""})
    page = alice.get("/notes/").data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert b"<script>alert(1)</script>" not in page


@pytest.mark.parametrize(
    ("title", "body", "message"),
    [
        ("   ", "x", b"Title is required."),
        ("t" * 101, "", b"Title must be at most 100"),
        ("t", "b" * 10_001, b"Note must be at most 10,000"),
    ],
)
def test_invalid_notes_are_rejected(alice, title, body, message):
    response = alice.post("/notes/new", data={"title": title, "body": body})
    assert message in response.data


def test_oversized_request_is_rejected(alice):
    """Threat D2: anything over 256 KB is refused before the app reads it."""
    response = alice.post("/notes/new", data={"title": "t", "body": "b" * 300_000})
    assert response.status_code == 413
