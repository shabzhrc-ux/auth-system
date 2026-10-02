"""Register / login / logout routes and the login_required decorator."""
from datetime import datetime, timedelta, timezone
from functools import wraps
import sqlite3

from flask import (Blueprint, current_app, flash, g, redirect,
                   render_template, request, session, url_for)

from db import get_db
from security import (DUMMY_HASH, hash_password, validate_registration,
                      verify_password)

bp = Blueprint("auth", __name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@bp.before_app_request
def load_current_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, email, created_at, last_login_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if g.user is None:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


@bp.route("/register", methods=("GET", "POST"))
def register():
    if g.user:
        return redirect(url_for("views.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = validate_registration(
            username, email, password, current_app.config["MIN_PASSWORD_LENGTH"])
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, hash_password(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
            else:
                flash("Account created. You can log in now.", "success")
                return redirect(url_for("auth.login"))

        for e in errors:
            flash(e, "error")
        return render_template("register.html", username=username, email=email), 400
    return render_template("register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("views.dashboard"))
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        cfg = current_app.config

        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()

        generic_error = "Wrong username or password."

        if user is None:
            verify_password(DUMMY_HASH, password)  # equalise timing
            flash(generic_error, "error")
            return render_template("login.html", identifier=identifier), 401

        # Lockout check
        if user["locked_until"] and _parse(user["locked_until"]) > _now():
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html", identifier=identifier), 429

        if not verify_password(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= cfg["MAX_FAILED_ATTEMPTS"]:
                locked_until = _iso(_now() + timedelta(minutes=cfg["LOCKOUT_MINUTES"]))
                attempts = 0
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
            flash(generic_error, "error")
            return render_template("login.html", identifier=identifier), 401

        # Success: reset counters, rotate session to prevent fixation
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
            (_iso(_now()), user["id"]),
        )
        db.commit()
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        return redirect(url_for("views.dashboard"))
    return render_template("login.html")


@bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
