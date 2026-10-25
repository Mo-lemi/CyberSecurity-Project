"""Sharing tests. Only a note's owner may share it or revoke access (threat E1)."""

import pytest

from securenotes.db import get_db


@pytest.fixture
def alice(make_user):
    browser = make_user("alice")
    browser.post("/notes/new", data={"title": "Birthday party", "body": "12 Main St"})
    return browser  # Alice owns note 1


@pytest.fixture
def bob(make_user):
    return make_user("bob")


@pytest.fixture
def carol(make_user):
    return make_user("carol")


def share(browser, username, note_id=1):
    return browser.post(
        f"/notes/{note_id}/share", data={"username": username}, follow_redirects=True
    )


def shares_of_note_1(app):
    with app.app_context():
        rows = get_db().execute(
            "SELECT users.username FROM shares JOIN users ON users.id = shares.user_id"
            " WHERE note_id = 1 ORDER BY users.username"
        ).fetchall()
    return [row[0] for row in rows]


# --- The owner shares and revokes -------------------------------------------


def test_owner_can_share_and_sees_who_has_access(app, alice, bob):
    response = share(alice, "bob")
    assert b"Shared with bob." in response.data
    assert shares_of_note_1(app) == ["bob"]
    assert b"Remove access" in alice.get("/notes/1").data


def test_owner_can_revoke_access(app, alice, bob):
    share(alice, "bob")
    bob_id = 2
    alice.post(f"/notes/1/shares/{bob_id}/revoke")
    assert shares_of_note_1(app) == []


@pytest.mark.parametrize(
    ("username", "message"),
    [
        ("nobody", b"No user with that name."),
        ("alice", b"You already own this note."),
    ],
)
def test_share_rejects_unknown_user_and_self(app, alice, username, message):
    assert message in share(alice, username).data
    assert shares_of_note_1(app) == []


def test_sharing_twice_is_rejected(app, alice, bob):
    share(alice, "bob")
    assert b"Already shared with bob." in share(alice, "bob").data
    assert shares_of_note_1(app) == ["bob"]


def test_deleting_a_note_removes_its_shares(app, alice, bob):
    share(alice, "bob")
    alice.post("/notes/1/delete")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 0


# --- Nobody but the owner can share or revoke (threat E1) --------------------


def test_stranger_cannot_share_someone_elses_note(app, alice, bob, carol):
    """Bob has no access to note 1, so he can't share it with Carol."""
    response = bob.post("/notes/1/share", data={"username": "carol"})
    assert response.status_code == 404
    assert shares_of_note_1(app) == []


def test_reader_cannot_reshare_or_revoke(app, alice, bob, carol):
    """Bob can read note 1, but sharing and revoking stay owner-only."""
    share(alice, "bob")
    assert bob.post("/notes/1/share", data={"username": "carol"}).status_code == 404
    assert bob.post("/notes/1/shares/2/revoke").status_code == 404
    assert shares_of_note_1(app) == ["bob"]


def test_share_and_revoke_must_be_post(alice):
    assert alice.get("/notes/1/share").status_code == 405
    assert alice.get("/notes/1/shares/2/revoke").status_code == 405


# --- What a reader can and can't do -------------------------------------------


def test_reader_can_view_shared_note_read_only(alice, bob):
    share(alice, "bob")
    page = bob.get("/notes/1")
    assert page.status_code == 200
    assert b"12 Main St" in page.data
    assert b"Shared by <strong>alice</strong>" in page.data
    # No owner controls on the reader's page.
    assert b"Delete note" not in page.data
    assert b"/notes/1/edit" not in page.data


def test_shared_note_appears_in_shared_with_me(alice, bob):
    share(alice, "bob")
    page = bob.get("/notes/").data
    assert b"Birthday party" in page
    assert b"from alice" in page


@pytest.mark.parametrize(
    ("method", "url", "data"),
    [
        ("get", "/notes/1/edit", None),
        ("post", "/notes/1/edit", {"title": "HACKED", "body": "x"}),
        ("post", "/notes/1/delete", None),
    ],
)
def test_reader_cannot_edit_or_delete(app, alice, bob, method, url, data):
    """Threat E1: read access must never become write access, even via Burp."""
    share(alice, "bob")
    assert getattr(bob, method)(url, data=data).status_code == 404
    with app.app_context():
        title = get_db().execute("SELECT title FROM notes WHERE id = 1").fetchone()[0]
    assert title == "Birthday party"


def test_readers_do_not_see_each_other(alice, bob, carol):
    """Design decision 39: sharing with Bob never reveals Carol to him."""
    share(alice, "bob")
    share(alice, "carol")
    assert b"carol" not in bob.get("/notes/1").data


def test_revoked_reader_loses_access_immediately(alice, bob):
    share(alice, "bob")
    alice.post("/notes/1/shares/2/revoke")
    assert bob.get("/notes/1").status_code == 404
    assert b"Birthday party" not in bob.get("/notes/").data


def test_sharing_with_bob_does_not_give_carol_access(alice, bob, carol):
    share(alice, "bob")
    assert carol.get("/notes/1").status_code == 404
