import sqlite3

import pytest

from securenotes.db import get_db


def test_init_db_command(app):
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert "Initialised the database." in result.output


def test_note_cannot_belong_to_a_missing_user(app):
    """SQLite ignores foreign keys unless get_db() switches them on."""
    with app.app_context():
        with pytest.raises(sqlite3.IntegrityError):
            get_db().execute(
                "INSERT INTO notes (owner_id, title, body) VALUES (999, 't', 'b')"
            )
