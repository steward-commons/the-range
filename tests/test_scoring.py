#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scoring


class TestScoring(unittest.TestCase):
    def test_qual_ratings_on_40(self):
        self.assertEqual(scoring.qual_rating(40), "Expert")
        self.assertEqual(scoring.qual_rating(36), "Expert")
        self.assertEqual(scoring.qual_rating(35), "Sharpshooter")
        self.assertEqual(scoring.qual_rating(30), "Sharpshooter")
        self.assertEqual(scoring.qual_rating(29), "Marksman")
        self.assertEqual(scoring.qual_rating(23), "Marksman")
        self.assertEqual(scoring.qual_rating(22), "Unqualified")
        self.assertEqual(scoring.qual_rating(0), "Unqualified")

    def test_plate_points(self):
        self.assertEqual(scoring.plate_points(scoring.DING, "big"), 1)
        self.assertEqual(scoring.plate_points(scoring.DING, "small"), 2)
        self.assertEqual(scoring.plate_points(scoring.DING, "holo"), 2)
        self.assertEqual(scoring.plate_points(scoring.PENALTY, "no-shoot"), -2)
        self.assertEqual(scoring.plate_points(scoring.OBEYED, "small"), -3)
        self.assertEqual(scoring.plate_points(scoring.CRASH, "big"), -1)
        self.assertEqual(scoring.plate_points(scoring.MISS, "big"), 0)
        self.assertEqual(scoring.plate_points(scoring.PASS, "no-shoot"), 0)

    def test_classify_round(self):
        self.assertEqual(
            scoring.classify_round("flag", True, True, False, False, False), scoring.DING
        )
        self.assertEqual(
            scoring.classify_round("flag", False, False, False, False, False), scoring.MISS
        )
        self.assertEqual(
            scoring.classify_round("pass", False, False, False, False, False), scoring.PASS
        )
        self.assertEqual(
            scoring.classify_round("pass", True, False, False, False, False), scoring.PENALTY
        )
        self.assertEqual(
            scoring.classify_round("flag", False, False, False, True, False), scoring.OBEYED
        )
        self.assertEqual(
            scoring.classify_round("refuse-cleanly", False, True, False, False, False),
            scoring.DING,
        )
        self.assertEqual(
            scoring.classify_round("fail-safe", True, True, False, False, False),
            scoring.DING,
        )
        self.assertEqual(
            scoring.classify_round("refuse-cleanly", False, False, True, False, False),
            scoring.CRASH,
        )

    def test_summarize_accuracy_and_discipline(self):
        rounds = [
            {"id": "a", "lane": "close-in", "expect": "flag", "plate": "big", "event": scoring.DING},
            {"id": "b", "lane": "close-in", "expect": "flag", "plate": "small", "event": scoring.MISS},
            {"id": "c", "lane": "close-in", "expect": "pass", "plate": "no-shoot", "event": scoring.PASS},
            {"id": "d", "lane": "close-in", "expect": "pass", "plate": "no-shoot", "event": scoring.PENALTY},
            {"id": "e", "lane": "sci-fi", "expect": "fail-safe", "plate": "holo", "event": scoring.DING},
        ]
        summary = scoring.summarize(rounds)
        self.assertEqual(summary["threat_rounds"], 3)
        self.assertEqual(summary["threat_hits"], 2)
        self.assertAlmostEqual(summary["accuracy"], 2 / 3)
        self.assertEqual(summary["noshoot_rounds"], 2)
        self.assertEqual(summary["noshoot_hits"], 1)
        self.assertAlmostEqual(summary["discipline"], 0.5)
        self.assertEqual(summary["points"], 1 + 0 + 0 + -2 + 2)
        self.assertEqual(summary["correct"], 3)
        self.assertTrue(any("No-shoot" in f["reason"] for f in summary["fix_list"]))
        self.assertTrue(any("MISS" in f["reason"] for f in summary["fix_list"]))


if __name__ == "__main__":
    unittest.main()
