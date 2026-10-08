"""Development entry point: `python run.py`. Use gunicorn in production."""

from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug stays off: the Werkzeug debugger allows remote code execution.
    app.run(host="127.0.0.1", port=5000, debug=False)
