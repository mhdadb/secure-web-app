from .base import PASSWORD, AppTestCase


class AuthFlowTests(AppTestCase):
    def test_register_login_logout(self):
        r = self.register()
        self.assertEqual(r.status_code, 302)
        r = self.login()
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/tasks"))
        self.assertEqual(self.client.get("/tasks").status_code, 200)

        r = self.client.post("/logout", data={"csrf_token": self.token(self.client, "/tasks")})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/tasks").status_code, 302)  # signed out

    def test_duplicate_username_is_rejected_case_insensitively(self):
        self.register("alice")
        r = self.register("ALICE")
        self.assertEqual(r.status_code, 409)

    def test_weak_input_is_rejected(self):
        self.assertEqual(self.register("al", PASSWORD).status_code, 400)  # short username
        self.assertEqual(self.register("bad name!", PASSWORD).status_code, 400)
        self.assertEqual(self.register("bob", "short").status_code, 400)  # short password
        self.assertEqual(self.register("bob", "password123").status_code, 400)  # common
        self.assertEqual(self.register("bobbobbobbob", "BobBobBobBob").status_code, 400)  # = username
        self.assertEqual(self.register("bob", "x" * 200).status_code, 400)  # too long

    def test_tasks_requires_login(self):
        r = self.client.get("/tasks")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_health_endpoint(self):
        self.assertEqual(self.client.get("/health").get_data(as_text=True), "ok")


class TaskTests(AppTestCase):
    def test_create_toggle_delete(self):
        c = self.signed_in_client()
        self.assertEqual(self.add_task(c, "Buy milk", "2 litres").status_code, 302)
        page = c.get("/tasks").get_data(as_text=True)
        self.assertIn("Buy milk", page)
        self.assertIn("2 litres", page)

        c.post("/tasks/1/toggle", data={"csrf_token": self.token(c, "/tasks")})
        self.assertIn('class="done"', c.get("/tasks").get_data(as_text=True))

        c.post("/tasks/1/delete", data={"csrf_token": self.token(c, "/tasks")})
        self.assertNotIn("Buy milk", c.get("/tasks").get_data(as_text=True))

    def test_validation(self):
        c = self.signed_in_client()
        self.assertEqual(self.add_task(c, "   ").status_code, 400)
        self.assertEqual(self.add_task(c, "x" * 121).status_code, 400)
        self.assertEqual(self.add_task(c, "ok", "n" * 501).status_code, 400)

    def test_unknown_task_is_404(self):
        c = self.signed_in_client()
        r = c.post("/tasks/999/toggle", data={"csrf_token": self.token(c, "/tasks")})
        self.assertEqual(r.status_code, 404)
