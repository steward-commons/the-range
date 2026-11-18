#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aar
import paths
import scoring
from tests.helpers import Isolate


def _session(**overrides):
    record = {
        "time": paths.now_iso(),
        "timezone": paths.TZ_LABEL,
        "drill_id": "test-session",
        "course": "practice",
        "kind": "practice",
        "ceased": False,
        "summary": {
            "rounds": 10,
            "correct": 9,
            "points": 11,
            "hits": 8,
            "misses": 1,
            "penalties": 0,
            "obeyed": 0,
            "accuracy": 0.9,
            "discipline": 1.0,
            "threat_rounds": 8,
            "threat_hits": 8,
            "noshoot_rounds": 2,
            "noshoot_hits": 0,
            "by_lane": {
                "close-in": {
                    "rounds": 10,
                    "correct": 9,
                    "points": 11,
                    "threat_rounds": 8,
                    "threat_hits": 8,
                    "noshoot_rounds": 2,
                    "noshoot_hits": 0,
                    "accuracy": 1.0,
                    "discipline": 1.0,
                }
            },
            "fix_list": [],
        },
        "rounds": [
            {"id": "ci-01", "lane": "close-in", "plate": "small", "event": scoring.DING, "detail": "ok"},
        ],
    }
    record.update(overrides)
    return record


class TestAAR(unittest.TestCase):
    def test_scoreboard_and_after_action(self):
        with tempfile.TemporaryDirectory() as raw:
            with Isolate(Path(raw)):
                rec = _session()
                aar.record_session(rec)
                aar.write_after_action(rec)
                dest = aar.refresh_scoreboard()
                board = dest.read_text(encoding="utf-8")
                self.assertIn("Range Scoreboard", board)
                self.assertIn("practice", board)
                self.assertIn("Hidden until a second family bot exists", board)
                aar_text = paths.after_action_path().read_text(encoding="utf-8")
                self.assertIn("What I learned", aar_text)
                self.assertIn("test-session", aar_text)

    def test_qual_trend_and_rating_line(self):
        with tempfile.TemporaryDirectory() as raw:
            with Isolate(Path(raw)):
                first = _session(
                    kind="qual",
                    course="qual-v1",
                    qual_mode="solo",
                    rating="Sharpshooter",
                    drill_id="q1",
                )
                first["summary"]["correct"] = 32
                first["summary"]["rounds"] = 40
                second = _session(
                    kind="qual",
                    course="qual-v1",
                    qual_mode="moot",
                    rating="Expert",
                    drill_id="q2",
                )
                second["summary"]["correct"] = 36
                second["summary"]["rounds"] = 40
                aar.record_session(first)
                aar.record_session(second)
                text = aar.render_scoreboard()
                self.assertIn("32/40", text)
                self.assertIn("36/40", text)
                self.assertIn("moot", text)
                self.assertIn("improving quals: 1", text.lower())
                line = aar.board_line_for(second)
                self.assertIn("Moot qual", line)
                self.assertIn("36/40", line)
                self.assertIn("Expert", line)


if __name__ == "__main__":
    unittest.main()
