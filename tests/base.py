import os
import re
import shutil
import tempfile
import unittest

from app import create_app

PASSWORD = "correct-horse-battery"


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": os.path.join(self.tmp, "test.db"),
                "SECRET_KEY": "test-secret-" + "x" * 32,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers
    def token(self, client=None, path="/login") -> str:
        client = client or self.client
        html = client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match, "CSRF token missing from page")
        return match.group(1)

    def register(self, username="alice", password=PASSWORD, client=None):
        client = client or self.client
        return client.post(
            "/register",
            data={"username": username, "password": password,
                  "csrf_token": self.token(client, "/register")},
        )

    def login(self, username="alice", password=PASSWORD, client=None):
        client = client or self.client
        return client.post(
            "/login",
            data={"username": username, "password": password,
                  "csrf_token": self.token(client, "/login")},
        )

    def signed_in_client(self, username="alice"):
        client = self.app.test_client()
        self.register(username, client=client)
        self.login(username, client=client)
        return client

    def add_task(self, client, title="Write report", notes=""):
        return client.post(
            "/tasks",
            data={"title": title, "notes": notes, "csrf_token": self.token(client, "/tasks")},
        )
