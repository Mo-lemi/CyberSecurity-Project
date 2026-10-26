"""Security event log tests (threat R1)."""

import json
import logging

import pytest

from .conftest import PASSWORD


def read_events(app):
    """Return every logged event as a list of dicts."""
    for handler in logging.getLogger("securenotes.security").handlers:
        handler.flush()
    with open(app.config["SECURITY_LOG"], encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def events_named(app, name):
    return [e for e in read_events(app) if e["event"] == name]


def test_login_success_and_failure_are_logged(app, client, make_user):
    make_user("alice")
    client.post("/auth/login", data={"username": "alice", "password": "wrong guess 123"})

    success = events_named(app, "login_succeeded")[0]
    assert success["username"] == "alice"
    assert success["user_id"] == 1
    assert success["ip"] == "127.0.0.1"
    assert "time" in success

    failure = events_named(app, "login_failed")[0]
    assert failure["username"] == "alice"


def test_passwords_are_never_logged(app, client, make_user):
    make_user("alice")
    client.post("/auth/login", data={"username": "alice", "password": "wrong guess 123"})
    with open(app.config["SECURITY_LOG"], encoding="utf-8") as f:
        log_text = f.read()
    assert PASSWORD not in log_text
    assert "wrong guess 123" not in log_text


def test_note_contents_are_never_logged(app, make_user):
    alice = make_user("alice")
    alice.post("/notes/new", data={"title": "Secret plan", "body": "12 Main St"})
    alice.post("/notes/1/delete")
    with open(app.config["SECURITY_LOG"], encoding="utf-8") as f:
        log_text = f.read()
    assert "Secret plan" not in log_text
    assert "12 Main St" not in log_text
    assert events_named(app, "note_deleted")[0]["note_id"] == 1


def test_log_injection_cannot_create_fake_lines(app, client):
    """A username containing a newline must not start a forged log entry."""
    fake = 'x\n{"event": "login_succeeded", "username": "admin"}'
    client.post("/auth/login", data={"username": fake, "password": "whatever"})
    events = read_events(app)  # every line must still be valid JSON
    assert [e["event"] for e in events] == ["login_failed"]


def test_long_usernames_are_cut_short(app, client):
    client.post("/auth/login", data={"username": "A" * 5000, "password": "whatever"})
    assert len(events_named(app, "login_failed")[0]["username"]) == 50


def test_snooping_on_other_notes_is_logged(app, make_user):
    """Bob trying Alice's note ID is exactly what the log should catch (A2, A3)."""
    alice = make_user("alice")
    alice.post("/notes/new", data={"title": "t", "body": "b"})
    bob = make_user("bob")
    bob.get("/notes/1")
    denied = events_named(app, "note_access_denied")[0]
    assert denied["user_id"] == 2
    assert denied["note_id"] == 1


@pytest.mark.parametrize(
    "event", ["user_registered", "logged_out", "note_shared", "share_revoked"]
)
def test_account_and_sharing_events_are_logged(app, make_user, event):
    alice = make_user("alice")
    make_user("bob")
    alice.post("/notes/new", data={"title": "t", "body": "b"})
    alice.post("/notes/1/share", data={"username": "bob"})
    alice.post("/notes/1/shares/2/revoke")
    alice.post("/auth/logout")
    assert events_named(app, event)
