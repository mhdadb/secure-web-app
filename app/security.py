"""Security helpers: CSRF protection, response headers, rate limiting,
input validation and the login_required decorator."""

from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, abort, g, redirect, request, session, url_for

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MIN_PASSWORD = 10
MAX_PASSWORD = 128
COMMON_PASSWORDS = {
    "password", "password1", "password123", "1234567890", "12345678910",
    "qwertyuiop", "iloveyou12", "letmein123", "admin12345", "welcome123",
}


# ----------------------------------------------------------------- validation
def validate_username(username: str) -> str | None:
    if not USERNAME_RE.match(username):
        return "Username must be 3 to 30 characters: letters, digits and underscore."
    return None


def validate_password(password: str, username: str = "") -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(password) > MAX_PASSWORD:
        return f"Password must be at most {MAX_PASSWORD} characters."
    if password.lower() in COMMON_PASSWORDS:
        return "That password is too common. Choose another."
    if username and password.lower() == username.lower():
        return "Password must not be the same as the username."
    return None


def clean_log_value(value: str, limit: int = 40) -> str:
    """Make user input safe to write to a log line (no newlines, bounded length)."""
    return re.sub(r"[^\x20-\x7e]", "?", value)[:limit]


# ----------------------------------------------------------------------- CSRF
def csrf_token() -> str:
    """Return the per-session token, creating it on first use."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def _csrf_check() -> None:
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "").encode("utf-8")
        expected = session.get("_csrf", "").encode("utf-8")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


# ---------------------------------------------------------------- rate limiter
class RateLimiter:
    """Sliding-window limiter kept in memory (one process).

    For several workers or servers, back it with Redis instead.
    """

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max = max_attempts
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.max

    def retry_after(self, key: str) -> int:
        with self._lock:
            now = time.monotonic()
            q = self._prune(key, now)
            if len(q) < self.max:
                return 0
            return max(1, int(self.window - (now - q[0])) + 1)

    def hit(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


# ---------------------------------------------------------------------- auth
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def client_ip() -> str:
    # Behind a reverse proxy, wrap the app in werkzeug's ProxyFix so this is the real client.
    return request.remote_addr or "unknown"


# ------------------------------------------------------------------- headers
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)


def init_app(app: Flask) -> None:
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.before_request(_csrf_check)

    @app.after_request
    def set_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if app.config.get("PRODUCTION"):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp
