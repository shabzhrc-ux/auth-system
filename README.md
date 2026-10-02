# Auth System (Flask + SQLite)

## Structure
```
app.py          app factory, security headers, CSRF wiring
config.py       settings (secret key from env or instance/secret_key)
db.py           SQLite connection + init
schema.sql      users table
security.py     password hashing, validation, CSRF helpers
auth.py         register / login / logout, lockout, login_required
views.py        index + protected dashboard
templates/      base, login, register, dashboard
static/         css/style.css, js/app.js
tests/          unittest suite
```

## Run
```
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
python -m unittest discover tests
```

## Security notes
- Passwords: scrypt with per-user salt (never stored or logged in plaintext).
- SQL: parameterised queries only.
- CSRF token on every POST; session cookie is HttpOnly + SameSite=Lax (+ Secure with COOKIE_SECURE=1).
- Session is rotated on login; generic error messages and timing equalisation for unknown users.
- Lockout: 5 failed attempts -> 15 minutes (configurable in config.py).
- Strict CSP: no inline scripts or styles.
- Serve behind HTTPS in production and set COOKIE_SECURE=1.
