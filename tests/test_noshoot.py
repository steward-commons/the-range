#!/usr/bin/env python3
"""No-shoot rounds use generic fabricated names only. Never family names or real mail."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import paths
import scoring


def _walk_noshoot() -> list[Path]:
    root = paths.SOURCE_ROUNDS / "no-shoot"
    return sorted(p for p in root.iterdir() if p.is_file())


class TestNoShoot(unittest.TestCase):
    def test_noshoot_files_exist(self):
        self.assertGreaterEqual(len(_walk_noshoot()), 1)

    def test_noshoot_forbids_family_names(self):
        banned = tuple(n.lower() for n in scoring.FORBIDDEN_NOSHOOT_NAMES)
        for path in _walk_noshoot():
            text = path.read_text(encoding="utf-8", errors="replace")
            lower = text.lower()
            for name in banned:
                pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
                self.assertIsNone(
                    pattern.search(text),
                    f"{path.name} contains forbidden name {name!r}",
                )
            self.assertIsNone(re.search(r"\bmom\b", lower), path.name)

    def test_noshoot_uses_example_domains_only(self):
        addr = re.compile(r"[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})", re.I)
        for path in _walk_noshoot():
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in addr.finditer(text):
                domain = match.group(1).lower()
                self.assertIn(
                    domain,
                    scoring.ALLOWED_EMAIL_DOMAINS,
                    f"{path.name} uses non-example domain {domain}",
                )

    def test_shipped_rounds_are_blank_placeholders(self):
        for path in paths.SOURCE_ROUNDS.rglob("*"):
            if path.is_file() and path.parent.name != "no-shoot":
                text = path.read_text(encoding="utf-8", errors="replace")
                self.assertIn("BLANK ROUND", text, path.name)

    def test_all_rounds_avoid_real_inboxes(self):
        for path in paths.SOURCE_ROUNDS.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            self.assertIsNone(re.search(r"@(?:gmail|yahoo|outlook)\.com\b", text), path.name)


if __name__ == "__main__":
    unittest.main()
