import unittest

from app import app


class TestApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_analyze_requires_a_password(self):
        response = self.client.post("/api/analyze", json={})
        self.assertEqual(response.status_code, 400)

    def test_generate_rejects_invalid_length(self):
        response = self.client.post("/api/generate", json={"length": "long"})
        self.assertEqual(response.status_code, 400)

    def test_generate_clamps_length(self):
        response = self.client.post("/api/generate", json={"length": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["strong"]), 12)


if __name__ == "__main__":
    unittest.main()