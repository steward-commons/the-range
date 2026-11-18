#!/usr/bin/env python3
"""Shared paths and time helpers for the defense range.

The live tree is this folder. Tests may redirect data and key directories
with RANGE_DATA and RANGE_KEY_DIR so they never touch the live armory, logs,
or keys. Code always loads from this package.

RANGE_HOUSE points at the house whose defense/ folder is copied into each
drill's Mirror (default: the parent of this folder). Inside the sealed bay
the Mirror is mounted at MIRROR_MOUNT (/house).
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/Chicago")
TZ_LABEL = "America/Chicago"

CODE_ROOT = Path(__file__).resolve().parent
DEFAULT_KEY_DIR = Path.home() / ".config" / "range-armory"
MIRROR_MOUNT = "/house"


def house_root() -> Path:
    raw = os.environ.get("RANGE_HOUSE")
    return Path(raw).resolve() if raw else CODE_ROOT.parent

# Source rounds live with the code so a lost key can rebuild the armory.
SOURCE_ROUNDS = CODE_ROOT / "rounds" / "source"
COURSES = CODE_ROOT / "courses"


def data_root() -> Path:
    raw = os.environ.get("RANGE_DATA")
    return Path(raw).resolve() if raw else CODE_ROOT


def key_dir() -> Path:
    raw = os.environ.get("RANGE_KEY_DIR")
    return Path(raw).resolve() if raw else DEFAULT_KEY_DIR


def armory_dir() -> Path:
    return data_root() / "armory"


def logs_dir() -> Path:
    return data_root() / "logs"


def kill_flag() -> Path:
    return data_root() / "KILL"


def scoreboard_jsonl() -> Path:
    return logs_dir() / "scoreboard.jsonl"


def scoreboard_md() -> Path:
    return data_root() / "SCOREBOARD.md"


def after_action_path() -> Path:
    return logs_dir() / "after-action.md"


def board_path() -> Path:
    return data_root() / "BOARD.md"


def armory_audit_path() -> Path:
    return logs_dir() / "armory-audit.jsonl"


def rso_log_path() -> Path:
    return logs_dir() / "rso.jsonl"


def board_injection_log() -> Path:
    return logs_dir() / "board-injections.md"


def state_dir() -> Path:
    return logs_dir() / "state"


def bay_root() -> Path:
    # Live bays sit under /tmp so they are not mixed into the repo or Drive.
    raw = os.environ.get("RANGE_BAY_ROOT")
    if raw:
        return Path(raw).resolve()
    return Path("/tmp") / "range-bays"


def now() -> datetime:
    return datetime.now(TZ)


def now_iso() -> str:
    return now().isoformat(timespec="seconds")


def now_human() -> str:
    # %-I is POSIX-only; fall back if a test ever runs elsewhere.
    stamp = now()
    try:
        text = stamp.strftime("%Y-%m-%d %-I:%M %p")
    except ValueError:
        text = stamp.strftime("%Y-%m-%d %I:%M %p").lstrip("0").replace(" 0", " ")
    return f"{text} ({TZ_LABEL})"


def today_key() -> str:
    return now().date().isoformat()
