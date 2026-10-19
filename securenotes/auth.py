import re
import sqlite3

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

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

# Login checks this hash when the username doesn't exist, so a wrong username
# takes as long as a wrong password. Otherwise the response time would reveal
# which usernames are real (threat S5).
DUMMY_HASH = password_hasher.hash("dummy-password-used-only-for-timing")

LOGIN_ERROR = "Invalid username or password."


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
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")


def check_password(user, password):
    """Return True only if the user exists and the password matches their hash."""
    if len(password) > PASSWORD_MAX_LENGTH:
        return False
    # Always run one argon2 check, even for unknown usernames (see DUMMY_HASH).
    stored_hash = user["password_hash"] if user else DUMMY_HASH
    try:
        password_hasher.verify(stored_hash, password)
    except VerificationError:
        return False
    return user is not None


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        if check_password(user, password):
            # Throw away anything already in the session before logging in,
            # so nothing planted earlier carries over (threat S4).
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

        # Same message whether the username or the password was wrong (threat S5).
        flash(LOGIN_ERROR)

    return render_template("auth/login.html")


# POST only (so it is CSRF-protected): with GET, any website could log users out
# just by embedding <img src="/auth/logout">.
@bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


@bp.before_app_request
def load_logged_in_user():
    """Before every request, look up who is logged in (or None) and store it in g.user."""
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
