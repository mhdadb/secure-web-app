"""Application factory for SecureTasks, a small task manager built to
demonstrate secure web development practices (see README for the OWASP map)."""

from __future__ import annotations

import logging
import os
import secrets
from datetime import timedelta

from flask import Flask, g, render_template, session
from werkzeug.middleware.proxy_fix import ProxyFix

from . import auth, db, security, tasks


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    production = os.environ.get("APP_ENV", "development") == "production"

    app.config.from_mapping(
        PRODUCTION=production,
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE", os.path.join("instance", "app.db")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production,
        # The __Host- prefix makes browsers reject the cookie unless it is Secure,
        # has Path=/ and no Domain attribute. It needs HTTPS, so production only.
        SESSION_COOKIE_NAME="__Host-session" if production else "session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=16 * 1024,
        LOGIN_MAX_ATTEMPTS=5,
        LOGIN_WINDOW_SECONDS=300,
        LOGIN_IP_MAX_ATTEMPTS=20,
        REGISTER_MAX_PER_HOUR=10,
        # Number of reverse proxies in front of the app (0 = none). Needed so rate
        # limits see the real client IP instead of the proxy's address.
        TRUSTED_PROXIES=int(os.environ.get("TRUSTED_PROXIES", "0")),
    )
    if test_config:
        app.config.update(test_config)

    key = app.config.get("SECRET_KEY")
    if not key:
        if app.config["PRODUCTION"]:
            raise RuntimeError("SECRET_KEY must be set in production")
        key = secrets.token_hex(32)  # development only: sessions reset on restart
        app.logger.warning("SECRET_KEY not set; using a temporary random key")
    elif app.config["PRODUCTION"] and len(key) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters in production")
    app.config["SECRET_KEY"] = key

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    # In-memory rate limiters, one set per app instance.
    app.extensions["limiters"] = {
        "login_user": security.RateLimiter(
            app.config["LOGIN_MAX_ATTEMPTS"], app.config["LOGIN_WINDOW_SECONDS"]
        ),
        "login_ip": security.RateLimiter(
            app.config["LOGIN_IP_MAX_ATTEMPTS"], app.config["LOGIN_WINDOW_SECONDS"]
        ),
        "register": security.RateLimiter(app.config["REGISTER_MAX_PER_HOUR"], 3600),
    }

    if app.config["TRUSTED_PROXIES"] > 0:
        n = app.config["TRUSTED_PROXIES"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    db.init_app(app)
    security.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(tasks.bp)

    @app.before_request
    def load_user():
        user_id = session.get("user_id")
        g.user = None
        if user_id is not None:
            g.user = db.get_db().execute(
                "SELECT id, username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if g.user is None:
                session.clear()

    @app.get("/health")
    def health():
        return "ok", 200, {"Content-Type": "text/plain; charset=utf-8"}

    # Generic error pages: never leak stack traces or internals.
    messages = {
        400: "The request could not be verified. Reload the page and try again.",
        404: "That page does not exist.",
        405: "That action is not allowed here.",
        413: "The request was too large.",
        429: "Too many requests. Please wait and try again.",
        500: "Something went wrong on our side.",
    }
    for code, text in messages.items():
        app.register_error_handler(
            code, lambda _e, code=code, text=text: (render_template("error.html", code=code, message=text), code)
        )

    return app
