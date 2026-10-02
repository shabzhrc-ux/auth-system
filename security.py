"""Password hashing, validation and CSRF helpers. No Flask routes live here."""
import re
import secrets
from hmac import compare_digest

from flask import abort, request, session
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str) -> str:
    # scrypt + random salt, stored together in one string.
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


# Used to burn the same CPU time when a username doesn't exist,
# so response timing doesn't reveal which accounts are real.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def validate_registration(username: str, email: str, password: str, min_len: int) -> list[str]:
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-32 characters: letters, numbers, _ . -")
    if not EMAIL_RE.match(email) or len(email) > 254:
        errors.append("Enter a valid email address.")
    if len(password) < min_len:
        errors.append(f"Password must be at least {min_len} characters.")
    if len(password) > 128:
        errors.append("Password must be 128 characters or fewer.")
    if password and password.lower() in {username.lower(), email.lower()}:
        errors.append("Password can't be the same as your username or email.")
    if password and not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        errors.append("Password must contain at least one letter and one number.")
    return errors


# ---- CSRF ----
def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def enforce_csrf() -> None:
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not compare_digest(sent, expected):
            abort(400, description="Invalid or missing CSRF token.")
