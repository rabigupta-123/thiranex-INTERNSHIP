import os
import unittest

# Point database to an isolated test db
test_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_passwords.db")
os.environ["PASSWORDS_DB_PATH"] = test_db

from app import app
import database


class TestApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        if os.path.exists(test_db):
            os.remove(test_db)

    def tearDown(self):
        if os.path.exists(test_db):
            try:
                os.remove(test_db)
            except OSError:
                pass

    def test_index_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Password Strength Analyzer", response.data)

    def test_analyze_requires_a_password(self):
        response = self.client.post("/api/analyze", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_analyze_rejects_password_too_long(self):
        response = self.client.post("/api/analyze", json={"password": "A" * 257})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_analyze_valid_password(self):
        response = self.client.post("/api/analyze", json={"password": "TestPassword123!"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("score", data)
        self.assertIn("label", data)
        self.assertIn("entropy", data)
        self.assertIn("crack_time", data)
        self.assertIn("checks", data)
        self.assertIn("suggestions", data)
        self.assertIn("brute_force", data)
        self.assertFalse(data["reused"])

    def test_generate_rejects_invalid_length(self):
        response = self.client.post("/api/generate", json={"length": "long"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_generate_clamps_length(self):
        # Clamps lower bound to 12
        response = self.client.post("/api/generate", json={"length": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["strong"]), 12)

        # Clamps upper bound to 64
        response_max = self.client.post("/api/generate", json={"length": 100})
        self.assertEqual(response_max.status_code, 200)
        self.assertEqual(len(response_max.get_json()["strong"]), 64)

    def test_generate_success(self):
        response = self.client.post("/api/generate", json={"length": 24})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data["strong"]), 24)
        self.assertIn("passphrase", data)
        self.assertIn("entropy_estimate", data)

    def test_stats_endpoint(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        self.assertIn("history_count", response.get_json())

    def test_save_validation(self):
        # Missing password
        r1 = self.client.post("/api/save", json={})
        self.assertEqual(r1.status_code, 400)

        # Non-string password
        r2 = self.client.post("/api/save", json={"password": 12345})
        self.assertEqual(r2.status_code, 400)

        # Too long
        r3 = self.client.post("/api/save", json={"password": "x" * 257})
        self.assertEqual(r3.status_code, 400)

    def test_save_and_reuse_flow(self):
        # 1. Save new password
        res1 = self.client.post("/api/save", json={"password": "MySecretPassphrase123!"})
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.get_json()["status"], "saved")
        self.assertEqual(res1.get_json()["history_count"], 1)

        # 2. Saving same password again returns already_saved
        res2 = self.client.post("/api/save", json={"password": "MySecretPassphrase123!"})
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_json()["status"], "already_saved")

        # 3. Analyze warns about reuse
        res3 = self.client.post("/api/analyze", json={"password": "MySecretPassphrase123!"})
        self.assertEqual(res3.status_code, 200)
        self.assertTrue(res3.get_json()["reused"])

    def test_hash_endpoint(self):
        # Missing password
        r1 = self.client.post("/api/hash", json={})
        self.assertEqual(r1.status_code, 400)

        # Non-string password
        r2 = self.client.post("/api/hash", json={"password": 99999})
        self.assertEqual(r2.status_code, 400)

        # Valid password
        r3 = self.client.post("/api/hash", json={"password": "SuperSecretPassword1!"})
        self.assertEqual(r3.status_code, 200)
        data = r3.get_json()
        self.assertIn("sha256", data)
        self.assertIn("sha512", data)
        self.assertIn("pbkdf2_600k", data)
        self.assertIn("hmac_sha256", data)


if __name__ == "__main__":
    unittest.main()