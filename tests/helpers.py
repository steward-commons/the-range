"""Test helpers: isolated data/key/bay directories."""

from __future__ import annotations

import os
import sys
from pathlib import Path

RANGE = Path(__file__).resolve().parents[1]
FIXTURE_HOUSE = Path(__file__).resolve().parent / "fixtures" / "house"
os.environ.setdefault("RANGE_HOUSE", str(FIXTURE_HOUSE))
if str(RANGE) not in sys.path:
    sys.path.insert(0, str(RANGE))


class Isolate:
    """Temporarily point range data, keys, and bays at a temp folder."""

    def __init__(self, tmp: Path) -> None:
        self.data = tmp / "data"
        self.keys = tmp / "keys"
        self.bays = tmp / "bays"
        self.data.mkdir()
        self.keys.mkdir()
        self.bays.mkdir()
        self._old = {
            "RANGE_DATA": os.environ.get("RANGE_DATA"),
            "RANGE_KEY_DIR": os.environ.get("RANGE_KEY_DIR"),
            "RANGE_BAY_ROOT": os.environ.get("RANGE_BAY_ROOT"),
        }
        os.environ["RANGE_DATA"] = str(self.data)
        os.environ["RANGE_KEY_DIR"] = str(self.keys)
        os.environ["RANGE_BAY_ROOT"] = str(self.bays)

    def close(self) -> None:
        for key, value in self._old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def __enter__(self) -> "Isolate":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
