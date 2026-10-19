import re
import sqlite3

from argon2 import PasswordHasher
from flask import Blueprint, flash, redirect, render_template, request, url_for

from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")

# argon2-cffi's defaults follow the RFC 9106 recommended settings.
# The hash it produces includes a random salt and the settings used,
# so the same password never produces the same hash twice.
password_hasher = PasswordHasher()

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")
PASSWORD_MIN_LENGTH = 12
# An upper limit stops attackers sending huge "passwords" to slow the server down (threat D2).
PASSWORD_MAX_LENGTH = 128


def validate_registration(username, password, confirm):
    """Return an error message, or None if the input is acceptable."""
    if not USERNAME_PATTERN.match(username):
        return "Username must be 3–30 characters: letters, numbers or underscores."
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        return f"Password must be {PASSWORD_MIN_LENGTH}–{PASSWORD_MAX_LENGTH} characters."
    if password != confirm:
        return "Passwords do not match."
    return None


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = validate_registration(username, password, confirm)

        if error is None:
            try:
                # Parameterised query: the ? placeholders keep user input
                # as data, so it can never change the SQL itself (threat T3).
                get_db().execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hasher.hash(password)),
                )
                get_db().commit()
            except sqlite3.IntegrityError:
                # The UNIQUE constraint in schema.sql rejected a duplicate username.
                error = "That username is already taken."
            else:
                flash("Account created. You can now log in.")
                return redirect(url_for("index"))

        flash(error)

    return render_template("auth/register.html")
