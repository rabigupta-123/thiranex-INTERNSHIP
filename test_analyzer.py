"""Unit tests for the Password Strength Analyzer core logic.

Run with:
    python -m unittest test_analyzer -v
"""

import unittest

from password_analyzer import (
    analyze_password,
    brute_force_resistance,
    effective_character_pool,
    estimate_entropy,
    suggest_passphrase,
    suggest_strong_password,
)


class TestAnalyzer(unittest.TestCase):
    def test_empty_password_is_very_weak(self):
        r = analyze_password("")
        self.assertEqual(r.label, "Very Weak")
        self.assertEqual(r.score, 0)

    def test_common_password_is_weak(self):
        r = analyze_password("password")
        self.assertIn(r.label, ["Weak", "Very Weak"])

    def test_short_password_scored_low_on_length(self):
        r = analyze_password("a")
        length = next(c for c in r.checks if c["name"] == "Length")
        self.assertFalse(length["passed"])
        self.assertLess(r.score, 40)

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

    def test_history_reuse(self):
        r = analyze_password("SamePass1!", password_history=["SamePass1!"])
        self.assertFalse(r.uniqueness)
        self.assertEqual(r.score, 0)

    def test_history_new_password(self):
        r = analyze_password("BrandNewPass1!", password_history=["OldPass1!"])
        self.assertTrue(r.uniqueness)

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


if __name__ == "__main__":
    unittest.main()
