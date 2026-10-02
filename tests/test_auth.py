import os
import re
import sqlite3
import tempfile
import unittest

from app import create_app


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.fd, self.path = tempfile.mkstemp(suffix=".db")
        self.app = create_app({"TESTING": True, "DATABASE": self.path, "MAX_FAILED_ATTEMPTS": 3})
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.fd)
        os.unlink(self.path)

    def csrf(self, url="/login"):
        html = self.client.get(url).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def register(self, username="alice", email="alice@example.com", pw="correct horse 42"):
        return self.client.post("/register", data={
            "csrf_token": self.csrf("/register"), "username": username, "email": email,
            "password": pw, "confirm_password": pw})

    def login(self, ident="alice", pw="correct horse 42"):
        return self.client.post("/login", data={
            "csrf_token": self.csrf(), "identifier": ident, "password": pw})

    def test_password_is_hashed_not_plaintext(self):
        self.register()
        row = sqlite3.connect(self.path).execute("SELECT password_hash FROM users").fetchone()
        self.assertNotIn("correct horse", row[0])
        self.assertTrue(row[0].startswith("scrypt:"))

    def test_register_login_logout_flow(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.client.post("/logout", data={"csrf_token": self.csrf("/dashboard")})
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_login_by_email(self):
        self.register()
        self.assertEqual(self.login("alice@example.com").status_code, 302)

    def test_wrong_password_and_unknown_user_look_identical(self):
        self.register()
        a = self.login("alice", "wrong-password-1")
        b = self.login("nobody", "wrong-password-1")
        self.assertEqual(a.status_code, 401)
        self.assertEqual(b.status_code, 401)

    def test_lockout_after_repeated_failures(self):
        self.register()
        for _ in range(3):
            self.login("alice", "bad-password-9")
        self.assertEqual(self.login().status_code, 429)  # even the right password is blocked

    def test_duplicate_user_rejected(self):
        self.register()
        self.assertEqual(self.register().status_code, 400)

    def test_weak_password_rejected(self):
        self.assertEqual(self.register(pw="short1").status_code, 400)

    def test_csrf_required(self):
        r = self.client.post("/login", data={"identifier": "a", "password": "b"})
        self.assertEqual(r.status_code, 400)

    def test_dashboard_requires_login(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_sql_injection_attempt_fails_safely(self):
        self.register()
        self.assertEqual(self.login("' OR '1'='1", "x").status_code, 401)


if __name__ == "__main__":
    unittest.main()
