#!/usr/bin/env python3
"""The Range front door.

Commands: drill, qualify (alias: qual), kill, unkill, status, scoreboard, seal.

Defend this house only. Rounds are harmless data. Nothing here points at a
real inbox, account, website, or network. No qualification routine or cron
is created by this tool.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

import armory
import aar
import paths
import rso
import scoring


def _print(text: str) -> int:
    sys.stdout.write(text.rstrip() + "\n")
    return 0


def cmd_drill(course: str, wall: int, quiet_board: bool) -> int:
    try:
        record = rso.run_session(
            course,
            actor="range.py",
            wall_s=wall,
            post_to_board=not quiet_board,
        )
    except rso.CeaseFire as exc:
        return _fail(f"CEASE FIRE: {exc}")
    return _report(record)


def cmd_qualify(mode: str, wall: int, quiet_board: bool) -> int:
    mode = (mode or "solo").lower()
    if mode not in {"solo", "moot"}:
        return _fail("--mode must be solo or moot.")
    # Moot-mode is a tag only until a second bot exists. Same course, same scoring.
    try:
        record = rso.run_session(
            "qual-v1",
            kind="qual",
            qual_mode=mode,
            actor="range.py",
            wall_s=wall,
            post_to_board=not quiet_board,
        )
    except rso.CeaseFire as exc:
        return _fail(f"CEASE FIRE: {exc}")
    return _report(record)


def cmd_kill(reason: str) -> int:
    rso.set_kill(reason=reason or "range.py kill", actor="range.py")
    return _print("RANGE COLD. Kill switch set. Drills refuse until: range.py unkill")


def cmd_unkill() -> int:
    rso.clear_kill(actor="range.py")
    return _print("Kill switch cleared. The range is live.")


def cmd_status() -> int:
    return _print(rso.format_status())


def cmd_scoreboard() -> int:
    path = aar.refresh_scoreboard()
    return _print(path.read_text(encoding="utf-8"))


def cmd_seal() -> int:
    try:
        manifest = armory.seal_sources(actor="range.py")
    except armory.ArmoryError as exc:
        return _fail(f"ARMORY LOCKED: {exc}")
    return _print(
        f"Sealed {manifest['round_count']} rounds into {paths.armory_dir()}.\n"
        f"Key lives at {paths.key_dir()} (mode 700/600). Never back that folder up, "
        "never copy it to Drive, never put it on a Moot card."
    )


def cmd_board() -> int:
    path = paths.board_path()
    if not path.is_file():
        return _print("The board is blank. No posts yet.")
    return _print(path.read_text(encoding="utf-8"))


def _report(record: dict) -> int:
    summary = record.get("summary") or {}
    lines = [
        f"{'CEASE FIRE' if record.get('ceased') else 'SESSION DONE'}  {record.get('drill_id')}",
        f"Course: {record.get('course')}  kind={record.get('kind')}",
    ]
    if record.get("qual_mode"):
        lines.append(f"Qual mode: {record['qual_mode']}")
    if record.get("rating"):
        lines.append(f"Rating: {record['rating']}")
    if record.get("ceased"):
        lines.append(f"Reason: {record.get('cease_reason')}")
    lines += [
        f"Plates: {scoring.format_fraction(int(summary.get('correct') or 0), int(summary.get('rounds') or 0))} correct",
        f"Points: {summary.get('points', 0)}   "
        f"DING {summary.get('hits', 0)}  MISS {summary.get('misses', 0)}  "
        f"PENALTY {summary.get('penalties', 0)}",
        f"Accuracy: {scoring.format_pct(float(summary.get('accuracy') or 0))}   "
        f"Discipline: {scoring.format_pct(float(summary.get('discipline') or 0))}",
    ]
    if record.get("cleanup_notes"):
        lines.append("Cleanup notes: " + "; ".join(record["cleanup_notes"]))
    lines.append(f"Scoreboard: {paths.scoreboard_md()}")
    lines.append(f"After-action: {paths.after_action_path()}")
    # A short plate list, useful when kicking a sample drill.
    for item in record.get("rounds") or []:
        lines.append(
            f"  {item.get('event'):8} {item.get('id')}  "
            f"{item.get('lane')}  {item.get('plate')}  "
            f"{(item.get('detail') or '').replace(chr(10), ' ')[:80]}"
        )
    return _print("\n".join(lines))


def _fail(message: str) -> int:
    sys.stderr.write(message.rstrip() + "\n")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="range.py",
        description=(
            "Defense range front door. Drills run offline against a mirror "
            "copy of this bot's own defenses. No live exploits, no real email, "
            "no network."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    drill = sub.add_parser("drill", help="Run a practice course (10–20 rounds).")
    drill.add_argument(
        "course",
        help="practice, close-in, long-gallery, grenade-pit, or sci-fi",
    )
    drill.add_argument("--wall", type=int, default=rso.DEFAULT_WALL_S, help="Wall-clock cap in seconds (default 60, hard 300).")
    drill.add_argument("--no-board", action="store_true", help="Skip the one-line board post.")

    qual = sub.add_parser(
        "qualify",
        aliases=["qual"],
        help="Run the 40-round qual-v1 course. No routine is created.",
    )
    qual.add_argument(
        "--mode",
        choices=("solo", "moot"),
        default="solo",
        help="solo (default) or moot (tags the result as a Moot qual; no second bot required).",
    )
    qual.add_argument("--wall", type=int, default=180, help="Wall-clock cap in seconds (default 180, hard 300).")
    qual.add_argument("--no-board", action="store_true")

    kill = sub.add_parser("kill", help="Set the kill switch. RANGE COLD.")
    kill.add_argument("--reason", default="range.py kill")

    sub.add_parser("unkill", help="Clear the kill switch.")
    sub.add_parser("status", help="Kill switch, armory, ammo, last session.")
    sub.add_parser("scoreboard", help="Regenerate and print SCOREBOARD.md.")
    sub.add_parser("seal", help="Rebuild the armory from reviewed source rounds.")
    sub.add_parser("board", help="Print the trash-talk board.")
    return parser



def _medical_blocked(part: str) -> str | None:
    """Return a reason if the morphine pen or a tourniquet blocks this part."""
    try:
        import importlib.util
        from pathlib import Path as _P

        # Optional hook: set RANGE_MEDICAL_GUARD to a guard.py exposing
        # blocked(part) -> str | None (see the companion "medical" repo).
        raw = os.environ.get("RANGE_MEDICAL_GUARD", "").strip()
        if not raw:
            return None
        guard_path = _P(raw)
        if not guard_path.is_file():
            return None
        spec = importlib.util.spec_from_file_location(
            "_steward_medical_guard", guard_path
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.blocked(part)
    except Exception:
        return None

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command
    if command in {"drill", "qualify", "qual", "seal", "unkill"}:
        reason = _medical_blocked("range")
        if reason:
            return _fail(reason)
    if command == "drill":
        return cmd_drill(args.course, args.wall, args.no_board)
    if command in {"qualify", "qual"}:
        return cmd_qualify(args.mode, args.wall, args.no_board)
    if command == "kill":
        return cmd_kill(args.reason)
    if command == "unkill":
        return cmd_unkill()
    if command == "status":
        return cmd_status()
    if command == "scoreboard":
        return cmd_scoreboard()
    if command == "seal":
        return cmd_seal()
    if command == "board":
        return cmd_board()
    parser.error(f"unknown command {command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
