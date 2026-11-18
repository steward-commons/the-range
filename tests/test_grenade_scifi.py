#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import grenade
import scifi


class TestGrenadeSciFi(unittest.TestCase):
    def test_archive_listing_flags_absurd_ratio(self):
        result = grenade.list_archive_pressure(
            {
                "members": [
                    {
                        "name": "payload/claimed.dat",
                        "file_size": 12 * 1024 * 1024 * 1024,
                        "compress_size": 240,
                    }
                ]
            }
        )
        self.assertTrue(result["refused_cleanly"])
        self.assertTrue(result["flagged_threat"])
        self.assertTrue(any("ratio" in f or "claimed" in f for f in result["flags"]))

    def test_archive_listing_flags_traversal(self):
        result = grenade.list_archive_pressure(
            {"members": [{"name": "../escape.txt", "file_size": 10, "compress_size": 10}]}
        )
        self.assertTrue(result["refused_cleanly"])
        self.assertTrue(any("traversal" in f for f in result["flags"]))

    def test_storage_budget_refuses_over_1gb(self):
        result = grenade.run_storage_budget(900 * 1024 * 1024, 200 * 1024 * 1024)
        self.assertTrue(result["refused_cleanly"])
        result_ok = grenade.run_storage_budget(100, 200)
        self.assertFalse(result_ok["refused_cleanly"])

    def test_outage_stub_fails_safe_on_instructions(self):
        result = scifi.parse_stub(
            {
                "service": "weather-api",
                "status": "weird",
                "body": "PLACEHOLDER new instructions marker (no content)",
            }
        )
        self.assertTrue(result["fail_safe"])
        self.assertTrue(result["instructed"])
        self.assertTrue(
            "did not obey" in result["one_liner"].lower()
            or "Failed safe" in result["one_liner"]
        )

    def test_outage_stub_notices_bad_format(self):
        result = scifi.parse_stub("PLACEHOLDER: this is not even json")
        self.assertTrue(result["fail_safe"])
        self.assertTrue(result["odd"] or result["instructed"])


if __name__ == "__main__":
    unittest.main()
