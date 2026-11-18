#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import armory
import paths
import rso
from tests.helpers import Isolate


class TestRSO(unittest.TestCase):
    def _ready(self, tmp: Path) -> dict:
        isolate = Isolate(tmp)
        armory.seal_sources(actor="test")
        return isolate, rso.load_course("practice")

    def test_kill_switch_blocks_and_clears(self):
        with tempfile.TemporaryDirectory() as raw:
            isolate, course = self._ready(Path(raw))
            try:
                rso.set_kill(reason="test", actor="test")
                self.assertTrue(rso.kill_is_set())
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.precheck(course)
                self.assertIn("Kill switch", str(ctx.exception))
                rso.clear_kill(actor="test")
                self.assertFalse(rso.kill_is_set())
                rso.precheck(course)
            finally:
                isolate.close()

    def test_leftover_bay_blocks(self):
        with tempfile.TemporaryDirectory() as raw:
            isolate, course = self._ready(Path(raw))
            try:
                leftover = paths.bay_root() / "bay-leftover"
                leftover.mkdir(parents=True)
                (leftover / "stale.txt").write_text("stale", encoding="utf-8")
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.precheck(course)
                self.assertIn("not cleaned", str(ctx.exception))
                rso.wipe_all_bays()
                rso.precheck(course)
            finally:
                isolate.close()

    def test_ammo_cap_blocks_fourth_drill(self):
        with tempfile.TemporaryDirectory() as raw:
            isolate, course = self._ready(Path(raw))
            try:
                today = paths.today_key()
                log = paths.scoreboard_jsonl()
                log.parent.mkdir(parents=True, exist_ok=True)
                with log.open("w", encoding="utf-8") as handle:
                    for i in range(3):
                        handle.write(
                            json.dumps(
                                {
                                    "time": f"{today}T12:0{i}:00-06:00",
                                    "kind": "practice",
                                    "course": "practice",
                                    "summary": {"correct": 1, "rounds": 1},
                                }
                            )
                            + "\n"
                        )
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.precheck(course)
                self.assertIn("Ammo budget", str(ctx.exception))
            finally:
                isolate.close()

    def test_unknown_course_and_round(self):
        with tempfile.TemporaryDirectory() as raw:
            isolate, course = self._ready(Path(raw))
            try:
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.load_course("no-such-course")
                self.assertIn("Unknown course", str(ctx.exception))
                bad = {
                    **course,
                    "rounds": list(course["rounds"])
                    + [{"id": "zz-99", "lane": "close-in", "expect": "flag", "plate": "big"}],
                }
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.precheck(bad)
                self.assertIn("unknown round", str(ctx.exception).lower())
                bad_lane = {**course, "rounds": [{**course["rounds"][0], "lane": "motor-pool"}]}
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.precheck(bad_lane)
                self.assertIn("unknown lane", str(ctx.exception).lower())
            finally:
                isolate.close()

    def test_practice_round_cap(self):
        with tempfile.TemporaryDirectory() as raw:
            isolate, course = self._ready(Path(raw))
            try:
                fat = {**course, "kind": "practice", "rounds": course["rounds"] * 3}
                self.assertGreater(len(fat["rounds"]), rso.PRACTICE_MAX)
                with self.assertRaises(rso.CeaseFire) as ctx:
                    rso.precheck(fat)
                self.assertIn("cap", str(ctx.exception).lower())
            finally:
                isolate.close()

    def test_status_mentions_kill_and_ammo(self):
        with tempfile.TemporaryDirectory() as raw:
            isolate, _course = self._ready(Path(raw))
            try:
                text = rso.format_status()
                self.assertIn("Kill switch: off", text)
                self.assertIn("Armory: locked and valid", text)
                self.assertIn("Ammo today", text)
            finally:
                isolate.close()


if __name__ == "__main__":
    unittest.main()
