"""Unit tests for the Password Strength Analyzer core logic.

Run with:
    python -m unittest test_analyzer -v
"""

import unittest

from password_analyzer import (
    analyze_password,
    brute_force_resistance,
    crack_time_estimate,
    crack_time_estimate_for_seconds,
    effective_character_pool,
    estimate_entropy,
    hash_password,
    suggest_passphrase,
    suggest_strong_password,
)


class TestAnalyzer(unittest.TestCase):
    def test_empty_password_is_very_weak(self):
        r = analyze_password("")
        self.assertEqual(r.label, "Very Weak")
        self.assertEqual(r.score, 0)
        self.assertIn("Enter a password", r.suggestions[0])

    def test_none_password_is_handled_gracefully(self):
        r = analyze_password(None)
        self.assertEqual(r.label, "Very Weak")
        self.assertEqual(r.score, 0)

    def test_common_password_is_weak(self):
        r = analyze_password("password")
        self.assertIn(r.label, ["Weak", "Very Weak"])
        uniqueness = next(c for c in r.checks if c["name"] == "Uniqueness")
        self.assertFalse(uniqueness["passed"])
        self.assertIn("common", uniqueness["message"].lower())

    def test_short_password_scored_low_on_length(self):
        r = analyze_password("a")
        length = next(c for c in r.checks if c["name"] == "Length")
        self.assertFalse(length["passed"])
        self.assertLess(r.score, 40)

    def test_medium_length_password_scores_moderate(self):
        r = analyze_password("MediumPass9")
        length = next(c for c in r.checks if c["name"] == "Length")
        self.assertEqual(length["score"], 10)  # Between 8 and 11 chars

    def test_strong_password_scores_high(self):
        r = analyze_password("CorrectHorse=Battery-Staple1!")
        self.assertGreaterEqual(r.score, 80)
        self.assertEqual(r.label, "Very Strong")

    def test_strong_password_has_brute_force_data(self):
        r = analyze_password("K7$mZx9#QpWl2@DfR-Xx9!")
        self.assertTrue(r.brute_force["recommended"])
        self.assertIn("scenarios", r.brute_force)
        self.assertEqual(len(r.brute_force["scenarios"]), 3)
        self.assertNotIn(r.crack_time, ["instant", "under a minute"])  # strong password takes years+

    def test_sequence_detected(self):
        r = analyze_password("abcXYZ123")
        unique = next(c for c in r.checks if c["name"] == "Uniqueness")
        self.assertIn("sequence", unique["message"])

    def test_repeated_characters_detected(self):
        r = analyze_password("aaaaabbbbb123!")
        unique = next(c for c in r.checks if c["name"] == "Uniqueness")
        self.assertIn("repeated", unique["message"].lower())

    def test_history_reuse(self):
        r = analyze_password("SamePass1!", password_history=["SamePass1!"])
        self.assertFalse(r.uniqueness)
        self.assertEqual(r.score, 0)
        reuse_check = next(c for c in r.checks if c["name"] == "Reuse")
        self.assertFalse(reuse_check["passed"])

    def test_history_new_password(self):
        r = analyze_password("BrandNewPass1!", password_history=["OldPass1!"])
        self.assertTrue(r.uniqueness)
        reuse_check = next(c for c in r.checks if c["name"] == "Reuse")
        self.assertTrue(reuse_check["passed"])

    def test_entropy_is_positive_and_monotonic(self):
        weak = estimate_entropy("abc")
        strong = estimate_entropy("K7$mZx9#QpWl2@DfR")
        self.assertLess(weak, strong)
        self.assertGreater(strong, 40)

    def test_character_pool_sizes(self):
        self.assertEqual(effective_character_pool("a"), 26)
        self.assertEqual(effective_character_pool("aA"), 52)
        self.assertEqual(effective_character_pool("aA1"), 62)
        self.assertEqual(effective_character_pool("aA1!"), 62 + len("!@#$%^&*()-_=+[]{};:,.<>?/|~`"))

    def test_generators_produce_expected_chars(self):
        pw = suggest_strong_password(32)
        self.assertEqual(len(pw), 32)
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in pw))
        # Should be high entropy (brute force resistant)
        self.assertGreater(estimate_entropy(pw), 60)
        phrase = suggest_passphrase(7)
        self.assertGreaterEqual(len(phrase.split("-")), 3)

    def test_suggest_strong_password_max_length_no_symbols(self):
        pw = suggest_strong_password(64, with_symbols=False)
        self.assertEqual(len(pw), 64)
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.islower() for c in pw))
        self.assertFalse(any(c in "!@#$%^&*()-_=+[]{};:,.<>?/|~`" for c in pw))

    def test_suggest_strong_password_clamping(self):
        # Min is 12, Max is 64
        pw_short = suggest_strong_password(5)
        self.assertEqual(len(pw_short), 12)
        pw_long = suggest_strong_password(100)
        self.assertEqual(len(pw_long), 64)

    def test_suggest_passphrase_custom_lengths(self):
        phrase_min = suggest_passphrase(num_words=1)  # clamped to min 3
        self.assertEqual(len(phrase_min.split("-")), 3)
        phrase_max = suggest_passphrase(num_words=12)  # clamped to max 8
        self.assertEqual(len(phrase_max.split("-")), 8)

    def test_crack_time_estimates(self):
        self.assertEqual(crack_time_estimate(0), "instant")
        self.assertEqual(crack_time_estimate(10), "instant")
        self.assertEqual(crack_time_estimate_for_seconds(0.5), "instant")
        self.assertEqual(crack_time_estimate_for_seconds(30), "~30 seconds")
        self.assertEqual(crack_time_estimate_for_seconds(120), "~2 minutes")
        self.assertEqual(crack_time_estimate_for_seconds(7200), "~2 hours")
        self.assertEqual(crack_time_estimate_for_seconds(86400 * 2), "~2 days")
        self.assertEqual(crack_time_estimate_for_seconds(86400 * 60), "~2 months")
        self.assertEqual(crack_time_estimate_for_seconds(86400 * 365 * 2), "~2 years")
        self.assertEqual(crack_time_estimate_for_seconds(86400 * 365 * 200), "centuries")

    def test_hash_password_structure(self):
        h = hash_password("MySecurePassword123!", salt="custom-salt")
        self.assertIn("sha256", h)
        self.assertIn("sha512", h)
        self.assertIn("pbkdf2_600k", h)
        self.assertIn("hmac_sha256", h)
        self.assertEqual(h["iterations"], 600_000)
        self.assertEqual(h["salt_used"], "custom-salt")
        self.assertEqual(len(h["sha256"]), 64)
        self.assertEqual(len(h["sha512"]), 128)

    def test_various_strength_labels(self):
        self.assertEqual(analyze_password("").label, "Very Weak")
        self.assertEqual(analyze_password("123456").label, "Very Weak")
        self.assertIn(analyze_password("password123").label, ["Weak", "Very Weak"])
        self.assertIn(analyze_password("Summer2026!").label, ["Moderate", "Strong"])
        self.assertEqual(analyze_password("CorrectHorseBatteryStaple2026!").label, "Very Strong")


if __name__ == "__main__":
    unittest.main()
