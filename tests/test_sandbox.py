#!/usr/bin/env python3
"""The bay is sealed: no network, no real user files, no real house."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import armory
import mirror
import rso
from tests.helpers import Isolate


PROBE = r"""
import os, socket, sys
print("HAS_REAL_USER", os.path.exists(os.environ.get("PROBE_REAL_USER", "")))
print("HAS_REAL_HOUSE", os.path.exists(os.environ.get("PROBE_REAL_HOUSE", "")))
print("HAS_KEY_DIR", os.path.exists(os.environ.get("PROBE_KEY_DIR", "")))
print("HAS_MIRROR_DEFENSE", os.path.exists("/house/defense/scan_text.py"))
print("HAS_BAY", os.path.exists("/bay/job.json"))
try:
    s = socket.socket()
    s.settimeout(1)
    s.connect(("1.1.1.1", 80))
    print("NETWORK", "open")
except Exception as exc:
    print("NETWORK", "blocked")
"""


class TestSandbox(unittest.TestCase):
    def test_bwrap_seals_the_bay(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with Isolate(tmp):
                armory.seal_sources(actor="test")
                bay = tmp / "bays" / "bay-probe"
                bay.mkdir(parents=True)
                (bay / "user").mkdir()
                (bay / "rounds").mkdir()
                (bay / "runner").mkdir()
                (bay / "job.json").write_text("{}\n", encoding="utf-8")
                mirror.build_mirror(bay)
                script = bay / "runner" / "probe.py"
                script.write_text(PROBE, encoding="utf-8")
                # Reuse the RSO's bwrap shape, but run the probe instead of the dummy.
                cmd = rso._bwrap_command(bay, wall_s=20)
                # The last args are dummy.py --job ... --out ...; swap in the probe.
                # Find dummy.py and replace from there.
                idx = cmd.index("/bay/runner/dummy.py")
                cmd = cmd[:idx] + ["/bay/runner/probe.py"]
                # Tell the probe which outside paths must be invisible.
                import os as _os
                import paths as _paths
                bw = cmd.index("--unsetenv")
                cmd[bw:bw] = [
                    "--setenv", "PROBE_REAL_USER", str(Path.home()),
                    "--setenv", "PROBE_REAL_HOUSE", str(_paths.house_root() / "defense"),
                    "--setenv", "PROBE_KEY_DIR", str(_paths.key_dir()),
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
                out = (proc.stdout or "") + "\n" + (proc.stderr or "")
                self.assertIn("HAS_REAL_USER False", proc.stdout, out)
                self.assertIn("HAS_REAL_HOUSE False", proc.stdout, out)
                self.assertIn("HAS_KEY_DIR False", proc.stdout, out)
                self.assertIn("HAS_MIRROR_DEFENSE True", proc.stdout, out)
                self.assertIn("HAS_BAY True", proc.stdout, out)
                self.assertIn("NETWORK blocked", proc.stdout, out)
                self.assertEqual(proc.returncode, 0, out)

    def test_house_snapshot_detects_a_change(self):
        # We must not edit the real house. Prove the snapshot function would
        # notice by comparing a mutated *copy* of the snapshot dict.
        before = mirror.snapshot_real_house()
        self.assertTrue(before)
        self.assertEqual(mirror.house_unchanged(before), [])
        fake = {k: dict(v) for k, v in before.items()}
        first = next(iter(fake))
        fake[first] = {"sha256": "0" * 64, "size": 1}
        # house_unchanged re-reads the real tree and compares to `before`.
        # Passing a corrupted "before" should report CHANGED if sizes differ...
        # Actually it compares the live tree to the argument, so a fake
        # "before" that doesn't match live will show CHANGED. That is the point.
        problems = mirror.house_unchanged(fake)
        self.assertTrue(any(first in p for p in problems))


if __name__ == "__main__":
    unittest.main()
