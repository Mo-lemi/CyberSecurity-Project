from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db

bp = Blueprint("notes", __name__, url_prefix="/notes")

# Size limits stop anyone filling the database with huge notes (threat D2).
TITLE_MAX_LENGTH = 100
BODY_MAX_LENGTH = 10_000


def validate_note(title, body):
    """Return an error message, or None if the note is acceptable."""
    if not title:
        return "Title is required."
    if len(title) > TITLE_MAX_LENGTH:
        return f"Title must be at most {TITLE_MAX_LENGTH} characters."
    if len(body) > BODY_MAX_LENGTH:
        return f"Note must be at most {BODY_MAX_LENGTH:,} characters."
    return None


@bp.route("/")
@login_required
def index():
    # Only ever select the logged-in user's own notes.
    notes = get_db().execute(
        "SELECT id, title, updated_at FROM notes"
        " WHERE owner_id = ? ORDER BY updated_at DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("notes/index.html", notes=notes)


@bp.route("/new", methods=("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "")

        error = validate_note(title, body)
        if error is None:
            # The owner is always taken from the session, never from the form,
            # so nobody can create a note "as" another user.
            get_db().execute(
                "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                (g.user["id"], title, body),
            )
            get_db().commit()
            flash("Note saved.")
            return redirect(url_for("notes.index"))

        flash(error)

    return render_template("notes/create.html")
