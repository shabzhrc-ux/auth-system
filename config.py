"""Central configuration. Secrets come from the environment, never from code."""
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)


def _load_secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    key_file = INSTANCE_DIR / "secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


class Config:
    SECRET_KEY = _load_secret_key()
    DATABASE = os.environ.get("DATABASE_PATH", str(INSTANCE_DIR / "auth.db"))

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Auth policy
    MIN_PASSWORD_LENGTH = 10
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
