CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,          -- scrypt hash with per-user salt, never plaintext
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                      -- ISO-8601 UTC, NULL when not locked
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_login_at   TEXT
);
