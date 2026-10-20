from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

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


def get_owned_note(note_id):
    """Return the note only if the logged-in user owns it; otherwise stop with 404.

    This is the IDOR defence (threats I1, I2, T1). The owner check is part of the
    SQL query itself, so a note can never be loaded without it. "Not yours" and
    "doesn't exist" both give the same 404, so attackers can't tell which IDs exist.
    """
    note = get_db().execute(
        "SELECT id, title, body, created_at, updated_at FROM notes"
        " WHERE id = ? AND owner_id = ?",
        (note_id, g.user["id"]),
    ).fetchone()
    if note is None:
        abort(404)
    return note


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


@bp.route("/<int:note_id>")
@login_required
def view(note_id):
    return render_template("notes/view.html", note=get_owned_note(note_id))


@bp.route("/<int:note_id>/edit", methods=("GET", "POST"))
@login_required
def edit(note_id):
    note = get_owned_note(note_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "")

        error = validate_note(title, body)
        if error is None:
            # owner_id is checked again here as a second layer, in case this
            # code is ever changed and the check above is accidentally removed.
            get_db().execute(
                "UPDATE notes SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP"
                " WHERE id = ? AND owner_id = ?",
                (title, body, note_id, g.user["id"]),
            )
            get_db().commit()
            flash("Note updated.")
            return redirect(url_for("notes.view", note_id=note_id))

        flash(error)

    return render_template("notes/edit.html", note=note)


# POST only, so deleting requires a CSRF token: a link or <img> on another
# website can't delete notes.
@bp.route("/<int:note_id>/delete", methods=("POST",))
@login_required
def delete(note_id):
    get_owned_note(note_id)
    get_db().execute(
        "DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, g.user["id"])
    )
    get_db().commit()
    flash("Note deleted.")
    return redirect(url_for("notes.index"))
