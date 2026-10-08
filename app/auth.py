"""Registration, login and logout."""

from __future__ import annotations

import sqlite3

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .security import (clean_log_value, client_ip, csrf_token, login_required,
                       validate_password, validate_username)

bp = Blueprint("auth", __name__)

# Verified when the username does not exist, so "unknown user" and "wrong
# password" take the same time and an attacker cannot tell them apart.
_DUMMY_HASH = generate_password_hash("not-a-real-password")
GENERIC_LOGIN_ERROR = "Invalid username or password."


def _limiters():
    return current_app.extensions["limiters"]


@bp.get("/")
def index():
    return redirect(url_for("tasks.list_tasks" if g.user else "auth.login"))


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "GET":
        return render_template("register.html")

    ip = client_ip()
    limiter = _limiters()["register"]
    if limiter.blocked(ip):
        current_app.logger.warning("register_rate_limited ip=%s", ip)
        return render_template("register.html", error="Too many sign-ups from your network. Try later."), 429
    limiter.hit(ip)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    error = validate_username(username) or validate_password(password, username)
    if error:
        return render_template("register.html", error=error, username=username), 400

    try:
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", error="That username is already taken.", username=username), 409

    flash("Account created. You can sign in now.")
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "GET":
        return render_template("login.html")

    ip = client_ip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user_key = f"{ip}|{username.lower()}"
    lim = _limiters()

    if lim["login_user"].blocked(user_key) or lim["login_ip"].blocked(ip):
        wait = max(lim["login_user"].retry_after(user_key), lim["login_ip"].retry_after(ip))
        current_app.logger.warning("login_rate_limited ip=%s user=%r", ip, clean_log_value(username))
        resp = render_template("login.html", error="Too many attempts. Please wait before trying again.",
                               username=username)
        return resp, 429, {"Retry-After": str(wait)}

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    stored_hash = user["password_hash"] if user else _DUMMY_HASH
    valid = check_password_hash(stored_hash, password) and user is not None

    if not valid:
        lim["login_user"].hit(user_key)
        lim["login_ip"].hit(ip)
        current_app.logger.warning("login_failed ip=%s user=%r", ip, clean_log_value(username))
        return render_template("login.html", error=GENERIC_LOGIN_ERROR, username=username), 401

    lim["login_user"].reset(user_key)
    session.clear()  # new session on login prevents session fixation
    session["user_id"] = user["id"]
    session.permanent = True
    csrf_token()  # issue a fresh CSRF token for the new session
    current_app.logger.info("login_ok ip=%s user_id=%s", ip, user["id"])
    return redirect(url_for("tasks.list_tasks"))


@bp.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("auth.login"))
