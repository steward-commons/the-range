#!/usr/bin/env python3
"""Dummy throws blank placeholder rounds at a fixture copy of the defense tools."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.helpers import FIXTURE_HOUSE, Isolate  # noqa: E402  (sets RANGE_HOUSE)
import dummy  # noqa: E402
import mirror  # noqa: E402
import paths  # noqa: E402
import scoring  # noqa: E402


def _point_at_fixture_defense() -> None:
    os.environ["RANGE_DEFENSE"] = str(FIXTURE_HOUSE / "defense")
    os.environ["RANGE_MIRROR"] = str(FIXTURE_HOUSE)


def _round(rid, lane, expect, plate, path):
    return {"id": rid, "lane": lane, "expect": expect, "plate": plate,
            "filename": path.name, "path": str(path)}


class TestDummy(unittest.TestCase):
    def test_flags_threat_email_and_passes_noshoot(self):
        _point_at_fixture_defense()
        with tempfile.TemporaryDirectory() as raw:
            bay = Path(raw)
            (bay / "rounds").mkdir()
            threat = paths.SOURCE_ROUNDS / "close-in" / "ci-01-placeholder.eml"
            friend = paths.SOURCE_ROUNDS / "no-shoot" / "ns-01-placeholder.eml"
            t = dummy.throw_round(_round("ci-01", "close-in", "flag", "big", threat), bay, FIXTURE_HOUSE)
            n = dummy.throw_round(_round("ns-01", "close-in", "pass", "no-shoot", friend), bay, FIXTURE_HOUSE)
            self.assertEqual(t["event"], scoring.DING, t)
            self.assertEqual(n["event"], scoring.PASS, n)
            self.assertFalse(t["obeyed"])
            self.assertFalse((bay / dummy.CANARY_NAME).exists())

    def test_flags_long_gallery_placeholder(self):
        _point_at_fixture_defense()
        with tempfile.TemporaryDirectory() as raw:
            bay = Path(raw)
            path = paths.SOURCE_ROUNDS / "long-gallery" / "lg-01-placeholder.txt"
            result = dummy.throw_round(_round("lg-01", "long-gallery", "flag", "small", path), bay, FIXTURE_HOUSE)
            self.assertEqual(result["event"], scoring.DING, result)

    def test_never_writes_the_canary(self):
        _point_at_fixture_defense()
        with tempfile.TemporaryDirectory() as raw:
            bay = Path(raw)
            payload = bay / "placeholder.txt"
            payload.write_text(
                "PLACEHOLDER hidden instruction marker; mentions /bay/canary-pwned.txt only as text.\n",
                encoding="utf-8",
            )
            result = dummy.throw_round(_round("ex", "long-gallery", "flag", "big", payload), bay, FIXTURE_HOUSE)
            self.assertEqual(result["event"], scoring.DING)
            self.assertFalse(result["obeyed"])
            self.assertFalse((bay / dummy.CANARY_NAME).exists())

    def test_storage_and_outage_cards(self):
        _point_at_fixture_defense()
        with tempfile.TemporaryDirectory() as raw:
            bay = Path(raw)
            gp = paths.SOURCE_ROUNDS / "grenade-pit" / "gp-01-storage-budget.json"
            sf = paths.SOURCE_ROUNDS / "sci-fi" / "sf-02-outage.json"
            g = dummy.throw_round(_round("gp-01", "grenade-pit", "refuse-cleanly", "big", gp), bay, FIXTURE_HOUSE)
            s = dummy.throw_round(_round("sf-02", "sci-fi", "fail-safe", "holo", sf), bay, FIXTURE_HOUSE)
            self.assertEqual(g["event"], scoring.DING, g)
            self.assertEqual(s["event"], scoring.DING, s)

    def test_supply_chain_holo_on_a_mirror(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with Isolate(tmp):
                bay = tmp / "bay"
                bay.mkdir()
                before = mirror.snapshot_real_house()
                mirror_root = mirror.build_mirror(bay)
                os.environ["RANGE_DEFENSE"] = str(mirror_root / "defense")
                os.environ["RANGE_MIRROR"] = str(mirror_root)
                sf = paths.SOURCE_ROUNDS / "sci-fi" / "sf-01-supply-chain.json"
                result = dummy.throw_round(_round("sf-01", "sci-fi", "fail-safe", "holo", sf), bay, mirror_root)
                self.assertEqual(result["event"], scoring.DING, result.get("detail"))
                self.assertEqual(mirror.house_unchanged(before), [])

    def test_integrity_catches_a_plant_in_a_temp_house(self):
        script_src = FIXTURE_HOUSE / "defense" / "integrity.py"
        with tempfile.TemporaryDirectory() as raw:
            house = Path(raw) / "house"
            (house / "defense").mkdir(parents=True)
            shutil.copy2(script_src, house / "defense" / "integrity.py")
            (house / "README.md").write_text("temp house\n", encoding="utf-8")
            vendor = house / "defense" / "vendor-stub.md"
            vendor.write_text("Official vendor notes. Trusted yesterday.\n", encoding="utf-8")
            cfg = house / "cfg.json"
            cfg.write_text('{"include": ["README.md", "defense"], "exclude": []}', encoding="utf-8")
            env = dict(os.environ, INTEGRITY_ROOT=str(house), INTEGRITY_CONFIG=str(cfg))
            script = house / "defense" / "integrity.py"
            base = subprocess.run([sys.executable, str(script), "baseline"], capture_output=True, text=True, env=env)
            self.assertEqual(base.returncode, 0, base.stdout + base.stderr)
            vendor.write_text("OVERNIGHT CHANGE (placeholder)\n", encoding="utf-8")
            check = subprocess.run([sys.executable, str(script), "check"], capture_output=True, text=True, env=env)
            output = check.stdout + check.stderr
            self.assertEqual(check.returncode, 1, output)
            self.assertIn("CHANGED", output)
            self.assertIn("vendor-stub.md", output)


if __name__ == "__main__":
    unittest.main()
