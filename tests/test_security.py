import sqlite3
import threading

from app import create_app

from .base import PASSWORD, AppTestCase


class InjectionTests(AppTestCase):
    """A03: injection (SQL and XSS)."""

    def test_sql_injection_login_fails(self):
        self.register("alice")
        for payload in ("' OR '1'='1", "alice' --", "alice'; DROP TABLE users; --", '" OR ""="'):
            r = self.login(payload, "anything-at-all")
            self.assertEqual(r.status_code, 401, payload)
        # The users table is intact and the real user can still sign in.
        self.assertEqual(self.login("alice").status_code, 302)

    def test_sql_injection_in_password_field(self):
        self.register("alice")
        self.assertEqual(self.login("alice", "' OR '1'='1").status_code, 401)

    def test_sql_payload_is_stored_as_plain_text(self):
        c = self.signed_in_client()
        payload = "x'); DROP TABLE tasks; --"
        self.assertEqual(self.add_task(c, payload).status_code, 302)
        page = c.get("/tasks").get_data(as_text=True)
        self.assertIn("DROP TABLE tasks", page)  # displayed literally, not executed
        conn = sqlite3.connect(self.app.config["DATABASE"])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1)
        conn.close()

    def test_xss_is_escaped(self):
        c = self.signed_in_client()
        self.add_task(c, "<script>alert(1)</script>", '<img src=x onerror="alert(2)">')
        page = c.get("/tasks").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn('<img src=x onerror="alert(2)">', page)
        self.assertIn("&lt;script&gt;", page)

    def test_xss_in_username_is_escaped_in_header(self):
        # Usernames are validated on sign-up, but the template must be safe on its own too:
        # insert a hostile username directly into the database and render the page.
        c = self.signed_in_client("alice")
        conn = sqlite3.connect(self.app.config["DATABASE"])
        conn.execute("UPDATE users SET username = ? WHERE id = 1", ("<b>x</b>",))
        conn.commit()
        conn.close()
        page = c.get("/tasks").get_data(as_text=True)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)


class CsrfTests(AppTestCase):
    """A08/A01: state-changing requests need a valid CSRF token."""

    def test_login_without_token_is_rejected(self):
        self.register()
        r = self.client.post("/login", data={"username": "alice", "password": PASSWORD})
        self.assertEqual(r.status_code, 400)

    def test_wrong_token_is_rejected(self):
        c = self.signed_in_client()
        self.token(c, "/tasks")
        r = c.post("/tasks", data={"title": "x", "csrf_token": "forged"})
        self.assertEqual(r.status_code, 400)

    def test_every_post_endpoint_needs_a_token(self):
        c = self.signed_in_client()
        self.add_task(c)
        for path in ("/tasks", "/tasks/1/toggle", "/tasks/1/delete", "/logout"):
            self.assertEqual(c.post(path, data={"title": "x"}).status_code, 400, path)

    def test_token_from_another_session_is_rejected(self):
        a, b = self.app.test_client(), self.app.test_client()
        token_a = self.token(a, "/login")
        self.token(b, "/login")
        r = b.post("/login", data={"username": "x", "password": "y", "csrf_token": token_a})
        self.assertEqual(r.status_code, 400)


class AccessControlTests(AppTestCase):
    """A01: users must never see or change each other's data."""

    def test_user_cannot_touch_another_users_task(self):
        alice = self.signed_in_client("alice")
        bob = self.signed_in_client("bobby")
        self.add_task(alice, "Alice private task")

        self.assertNotIn("Alice private task", bob.get("/tasks").get_data(as_text=True))
        t = self.token(bob, "/tasks")
        self.assertEqual(bob.post("/tasks/1/toggle", data={"csrf_token": t}).status_code, 404)
        self.assertEqual(bob.post("/tasks/1/delete", data={"csrf_token": t}).status_code, 404)

        page = alice.get("/tasks").get_data(as_text=True)
        self.assertIn("Alice private task", page)
        self.assertNotIn('class="done"', page)

    def test_logout_requires_post(self):
        c = self.signed_in_client()
        self.assertEqual(c.get("/logout").status_code, 405)


class AuthHardeningTests(AppTestCase):
    """A07: identification and authentication."""

    def test_passwords_are_hashed(self):
        self.register()
        conn = sqlite3.connect(self.app.config["DATABASE"])
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
        conn.close()
        self.assertNotIn(PASSWORD, stored)
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_same_password_gets_different_hashes(self):
        self.register("alice")
        self.register("bobby")
        conn = sqlite3.connect(self.app.config["DATABASE"])
        hashes = [r[0] for r in conn.execute("SELECT password_hash FROM users")]
        conn.close()
        self.assertEqual(len(set(hashes)), 2)  # unique salts

    def test_error_message_does_not_reveal_which_part_was_wrong(self):
        self.register("alice")
        wrong_pw = self.login("alice", "wrong-password-here").get_data(as_text=True)
        no_user = self.login("nobody", "wrong-password-here").get_data(as_text=True)
        self.assertIn("Invalid username or password.", wrong_pw)
        self.assertIn("Invalid username or password.", no_user)

    def test_rate_limit_blocks_even_the_correct_password(self):
        self.register("alice")
        for _ in range(5):
            self.assertEqual(self.login("alice", "wrong-password-here").status_code, 401)
        r = self.login("alice", PASSWORD)  # correct, but the account is locked out for now
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)

    def test_rate_limit_is_per_ip_across_usernames(self):
        self.register("alice")
        for i in range(20):
            self.login(f"user{i}", "wrong-password-here")
        self.assertEqual(self.login("alice", PASSWORD).status_code, 429)

    def test_successful_login_resets_the_counter(self):
        self.register("alice")
        for _ in range(4):
            self.login("alice", "wrong-password-here")
        self.assertEqual(self.login("alice", PASSWORD).status_code, 302)

    def test_session_is_renewed_on_login(self):
        self.register()
        before = self.token(self.client, "/login")
        self.login()
        with self.client.session_transaction() as sess:
            self.assertNotEqual(sess.get("_csrf"), before)
            self.assertIn("user_id", sess)

    def test_session_cookie_flags(self):
        self.register()
        r = self.login()
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_registration_is_rate_limited(self):
        statuses = [self.register(f"user{i}_x").status_code for i in range(12)]
        self.assertEqual(statuses[-1], 429)


class HeadersAndConfigTests(AppTestCase):
    """A05: security misconfiguration."""

    def test_security_headers_present(self):
        h = self.client.get("/login").headers
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertNotIn("Strict-Transport-Security", h)  # only over HTTPS in production

    def test_static_files_can_be_cached(self):
        r = self.client.get("/static/style.css")
        r.close()
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Cache-Control"), "no-store")

    def test_no_inline_scripts_or_styles(self):
        page = self.client.get("/login").get_data(as_text=True)
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("style=", page.lower())

    def test_errors_do_not_leak_details(self):
        r = self.client.get("/does-not-exist")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", body)
        self.assertNotIn("Werkzeug", body)

    def test_oversized_request_is_rejected(self):
        r = self.client.post("/login", data={"username": "a" * 50_000, "password": "b"})
        self.assertEqual(r.status_code, 413)

    def test_production_requires_a_strong_secret_key(self):
        with self.assertRaises(RuntimeError):
            create_app({"PRODUCTION": True, "SECRET_KEY": None, "DATABASE": ":memory:"})
        with self.assertRaises(RuntimeError):
            create_app({"PRODUCTION": True, "SECRET_KEY": "short", "DATABASE": ":memory:"})

    def test_production_mode_hardening(self):
        import os, tempfile
        app = create_app({"PRODUCTION": True, "SECRET_KEY": "k" * 40,
                          "SESSION_COOKIE_SECURE": True,
                          "DATABASE": os.path.join(tempfile.mkdtemp(), "p.db")})
        h = app.test_client().get("/login").headers
        self.assertIn("max-age=31536000", h["Strict-Transport-Security"])


class ProxyTests(AppTestCase):
    def test_rate_limit_uses_forwarded_ip_only_when_proxy_is_trusted(self):
        import os, tempfile
        def build(proxies):
            return create_app({"SECRET_KEY": "k" * 40, "TRUSTED_PROXIES": proxies,
                               "DATABASE": os.path.join(tempfile.mkdtemp(), "p.db")})

        def attempts(app, ip):
            c = app.test_client()
            codes = []
            for _ in range(21):
                tok = self.token(c, "/login")
                r = c.post("/login", data={"username": "u", "password": "p", "csrf_token": tok},
                           headers={"X-Forwarded-For": ip}, environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
                codes.append(r.status_code)
            return codes

        # Trusted proxy: attacker A is blocked, but a different client B behind the same proxy is not.
        app = build(1)
        self.assertEqual(attempts(app, "198.51.100.1")[-1], 429)
        c = app.test_client()
        tok = self.token(c, "/login")
        r = c.post("/login", data={"username": "u", "password": "p", "csrf_token": tok},
                   headers={"X-Forwarded-For": "198.51.100.2"}, environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
        self.assertEqual(r.status_code, 401)

        # No trusted proxy: the header is ignored (cannot be spoofed to dodge limits).
        app = build(0)
        codes = attempts(app, "198.51.100.1")
        c = app.test_client()
        tok = self.token(c, "/login")
        spoof = c.post("/login", data={"username": "u", "password": "p", "csrf_token": tok},
                       headers={"X-Forwarded-For": "203.0.113.77"}, environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
        self.assertEqual(codes[-1], 429)
        self.assertEqual(spoof.status_code, 429)


class RateLimiterUnitTests(AppTestCase):
    def test_window_expires(self):
        from app.security import RateLimiter
        rl = RateLimiter(max_attempts=2, window_seconds=0)  # everything expires immediately
        rl.hit("k"); rl.hit("k")
        self.assertFalse(rl.blocked("k"))

    def test_thread_safety_smoke(self):
        from app.security import RateLimiter
        rl = RateLimiter(max_attempts=1000, window_seconds=60)
        threads = [threading.Thread(target=lambda: [rl.hit("k") for _ in range(50)]) for _ in range(8)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(len(rl._hits["k"]), 400)
