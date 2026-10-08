"""Task CRUD. Every query is scoped to the signed-in user (access control)."""

from __future__ import annotations

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .db import get_db
from .security import login_required

bp = Blueprint("tasks", __name__)

MAX_TITLE = 120
MAX_NOTES = 500


def _render(error: str | None = None, **form):
    rows = get_db().execute(
        "SELECT id, title, notes, done FROM tasks WHERE user_id = ? ORDER BY done, id DESC",
        (g.user["id"],),
    ).fetchall()
    status = 400 if error else 200
    return render_template("tasks.html", tasks=rows, error=error, **form), status


@bp.get("/tasks")
@login_required
def list_tasks():
    return _render()


@bp.post("/tasks")
@login_required
def create_task():
    title = request.form.get("title", "").strip()
    notes = request.form.get("notes", "").strip()
    if not title:
        return _render("Give the task a title.", title=title, notes=notes)
    if len(title) > MAX_TITLE:
        return _render(f"Title must be at most {MAX_TITLE} characters.", title=title, notes=notes)
    if len(notes) > MAX_NOTES:
        return _render(f"Notes must be at most {MAX_NOTES} characters.", title=title, notes=notes)

    db = get_db()
    db.execute(
        "INSERT INTO tasks (user_id, title, notes) VALUES (?, ?, ?)",
        (g.user["id"], title, notes),
    )
    db.commit()
    return redirect(url_for("tasks.list_tasks"))


def _owned_update(sql: str, task_id: int) -> None:
    """Run an UPDATE/DELETE restricted to the current user's rows.

    A task that belongs to someone else behaves exactly like a missing one (404),
    so IDs cannot be used to discover other users' data.
    """
    db = get_db()
    cur = db.execute(sql, (task_id, g.user["id"]))
    db.commit()
    if cur.rowcount == 0:
        abort(404)


@bp.post("/tasks/<int:task_id>/toggle")
@login_required
def toggle_task(task_id: int):
    _owned_update("UPDATE tasks SET done = 1 - done WHERE id = ? AND user_id = ?", task_id)
    return redirect(url_for("tasks.list_tasks"))


@bp.post("/tasks/<int:task_id>/delete")
@login_required
def delete_task(task_id: int):
    _owned_update("DELETE FROM tasks WHERE id = ? AND user_id = ?", task_id)
    return redirect(url_for("tasks.list_tasks"))
