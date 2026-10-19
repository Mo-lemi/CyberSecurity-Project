import sqlite3

import click
from flask import current_app, g
from flask.cli import with_appcontext


def get_db():
    """Return this request's database connection, opening it on first use."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        # Rows behave like dicts, so code can use row["username"] instead of row[1].
        g.db.row_factory = sqlite3.Row
        # SQLite ignores foreign keys unless this is switched on for each connection.
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    """Close the connection at the end of every request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create a fresh database from schema.sql (deletes existing data)."""
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))


@click.command("init-db")
@with_appcontext  # gives the command access to app config, also when run from tests
def init_db_command():
    """Command-line entry point: `flask --app securenotes init-db`."""
    init_db()
    click.echo("Initialised the database.")


def init_app(app):
    """Register the database functions with the app."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
