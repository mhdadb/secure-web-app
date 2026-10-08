# SecureTasks: a Security-First Flask Web App

A small task manager (sign up, sign in, add, complete and delete tasks) built to
show how the **OWASP Top 10** risks are handled in real code. Every control has an
automated test that tries the attack and checks that it fails.

Stack: Python, Flask, SQLite, Jinja2. No JavaScript.

## Run it locally

Requires Python 3.9 or newer.

```bash
git clone <your-repo-url>
cd secure-web-app
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py                                       # http://127.0.0.1:5000
```

In development a temporary secret key is generated, so sessions reset when the
server restarts.

## OWASP Top 10 coverage

| OWASP category | What this project does | Where | Test |
|---|---|---|---|
| **A01 Broken access control** | Every task query is filtered by the signed-in user's id. Another user's task returns 404, identical to a missing task, so IDs reveal nothing. | `tasks.py` | `AccessControlTests` |
| **A02 Cryptographic failures** | Passwords hashed with scrypt and a unique salt (Werkzeug). Secret key comes from the environment and must be 32+ characters in production. Session cookie is `HttpOnly`, `SameSite=Lax`, `Secure` and `__Host-` prefixed in production. HSTS enabled in production. | `auth.py`, `__init__.py` | `AuthHardeningTests`, `HeadersAndConfigTests` |
| **A03 Injection** | All SQL uses `?` placeholders (no string building). Jinja2 auto-escapes all output. A strict Content-Security-Policy blocks inline and external scripts. | `db.py`, templates, `security.py` | `InjectionTests` |
| **A04 Insecure design** | Login attempts are limited per IP+username (5 per 5 min) and per IP (20 per 5 min). Sign-ups limited per IP. Request bodies capped at 16 KB. Password policy: 10 to 128 characters, no common passwords. | `security.py`, `auth.py` | `AuthHardeningTests` |
| **A05 Security misconfiguration** | Security headers on every response (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP). `Cache-Control: no-store` on dynamic pages. Debug mode off. Generic error pages with no stack traces. | `security.py`, `__init__.py` | `HeadersAndConfigTests` |
| **A06 Vulnerable components** | Only two dependencies (Flask, gunicorn) with version ranges. Check regularly with `pip-audit`. | `requirements.txt` | n/a |
| **A07 Authentication failures** | One generic error for unknown user and wrong password. A dummy hash is verified for unknown users so response time does not reveal which usernames exist. New session on login (prevents session fixation). 30-minute session lifetime. Logout is a POST. | `auth.py` | `AuthHardeningTests` |
| **A08 Integrity failures (CSRF)** | Every state-changing request needs a per-session CSRF token, compared in constant time. | `security.py` | `CsrfTests` |
| **A09 Logging and monitoring** | Failed logins, successful logins and rate-limit hits are logged with the IP. Usernames are sanitised before logging (no log injection). Passwords are never logged. | `auth.py` | n/a |
| **A10 SSRF** | Not applicable: the app makes no outbound requests. | n/a | n/a |

## Tests

```bash
python -m unittest -v
```

38 tests. Examples of what they do:

- Send `' OR '1'='1` and `'; DROP TABLE users; --` to the login form and confirm
  login fails and the tables survive.
- Store `<script>alert(1)</script>` as a task title and confirm it is shown as text.
- Submit every POST endpoint without a CSRF token, or with another session's token.
- Sign in as a second user and try to toggle and delete the first user's task.
- Make 5 wrong attempts, then confirm even the correct password is blocked (429).
- Confirm a forged `X-Forwarded-For` header cannot dodge the rate limit.

## Deploy

Example for Render or a similar host:

| Setting | Value |
|---|---|
| Build command | `pip install -r requirements.txt` |
| Start command | `gunicorn --workers 1 --threads 4 'app:create_app()'` (also in `Procfile`) |
| `APP_ENV` | `production` |
| `SECRET_KEY` | output of `python -c "import secrets; print(secrets.token_hex(32))"` |
| `TRUSTED_PROXIES` | `1` when the host puts a reverse proxy in front of the app |
| `DATABASE` | path on a persistent disk (free tiers often wipe the file system) |

Things to know:

- The rate limiter is **in memory**, so it is per process. The start command uses
  one worker for that reason. For several workers or servers, move the counters to
  Redis.
- `TRUSTED_PROXIES` matters: without it, all visitors behind the host's proxy share
  one IP address and one rate-limit bucket.
- Serve over HTTPS only. Production mode sets `Secure` cookies, so sign-in will not
  work over plain HTTP.

## Project structure

```
app/
  __init__.py    app factory, config, error pages
  auth.py        register, login, logout
  tasks.py       task CRUD scoped to the current user
  security.py    CSRF, headers, rate limiter, validation
  db.py          SQLite with parameterised queries
  templates/     Jinja2 templates
  static/        stylesheet
tests/           38 tests
run.py           development entry point
```

## Limitations and ideas

- SQLite suits a demo. Use PostgreSQL for real traffic.
- No email verification or password reset.
- Add two-factor authentication (TOTP) and check passwords against a breach list
  such as Have I Been Pwned (k-anonymity API).
- Not a substitute for a professional security review.

## License

MIT
