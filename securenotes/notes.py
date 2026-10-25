import sqlite3

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


def get_readable_note(note_id):
    """Return the note if the user owns it OR it was shared with them; otherwise 404.

    Used ONLY for viewing. Anything that changes a note uses get_owned_note()
    instead, so readers can never edit, delete or share (threat E1).
    """
    note = get_db().execute(
        "SELECT notes.id, notes.owner_id, notes.title, notes.body, notes.updated_at,"
        " users.username AS owner_name"
        " FROM notes JOIN users ON users.id = notes.owner_id"
        " WHERE notes.id = ? AND (notes.owner_id = ? OR EXISTS ("
        "   SELECT 1 FROM shares WHERE shares.note_id = notes.id AND shares.user_id = ?"
        " ))",
        (note_id, g.user["id"], g.user["id"]),
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
    # Notes other people have shared with the logged-in user.
    shared_notes = get_db().execute(
        "SELECT notes.id, notes.title, notes.updated_at, users.username AS owner_name"
        " FROM shares"
        " JOIN notes ON notes.id = shares.note_id"
        " JOIN users ON users.id = notes.owner_id"
        " WHERE shares.user_id = ? ORDER BY notes.updated_at DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("notes/index.html", notes=notes, shared_notes=shared_notes)


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
    note = get_readable_note(note_id)
    is_owner = note["owner_id"] == g.user["id"]

    # Only the owner sees who has access; readers never see each other.
    shared_with = []
    if is_owner:
        shared_with = get_db().execute(
            "SELECT users.id, users.username FROM shares"
            " JOIN users ON users.id = shares.user_id"
            " WHERE shares.note_id = ? ORDER BY users.username",
            (note_id,),
        ).fetchall()

    return render_template(
        "notes/view.html", note=note, is_owner=is_owner, shared_with=shared_with
    )


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


@bp.route("/<int:note_id>/share", methods=("POST",))
@login_required
def share(note_id):
    # get_owned_note: only the owner may share (threat E1).
    get_owned_note(note_id)
    username = request.form.get("username", "").strip()

    reader = get_db().execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if reader is None:
        # Reveals whether a username exists: an accepted risk, see threat S5.
        flash("No user with that name.")
    elif reader["id"] == g.user["id"]:
        flash("You already own this note.")
    else:
        try:
            get_db().execute(
                "INSERT INTO shares (note_id, user_id) VALUES (?, ?)",
                (note_id, reader["id"]),
            )
            get_db().commit()
            flash(f"Shared with {username}.")
        except sqlite3.IntegrityError:
            # The (note_id, user_id) primary key rejected a duplicate share.
            flash(f"Already shared with {username}.")

    return redirect(url_for("notes.view", note_id=note_id))


@bp.route("/<int:note_id>/shares/<int:user_id>/revoke", methods=("POST",))
@login_required
def revoke(note_id, user_id):
    get_owned_note(note_id)  # only the owner may revoke access
    get_db().execute(
        "DELETE FROM shares WHERE note_id = ? AND user_id = ?", (note_id, user_id)
    )
    get_db().commit()
    flash("Access removed.")
    return redirect(url_for("notes.view", note_id=note_id))
