#!/usr/bin/env python3
"""Range Safety Officer: dumb, strict, and loud.

Pre-checks, the kill switch, the ammo budget, the bwrap sandbox, cease fire,
and "last bot out takes the trash." There is no AI judgment in this file.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import armory
import aar
import mirror
import paths
import scoring

MAX_DRILLS_PER_DAY = 3
PRACTICE_MIN = 10
PRACTICE_MAX = 20
QUAL_ROUNDS = 40
DEFAULT_WALL_S = 60
HARD_WALL_S = 300
MEMORY_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB address space cap
MAX_PROCS = 128

LANES = {"close-in", "long-gallery", "grenade-pit", "sci-fi"}
KNOWN_COURSES = {
    "practice",
    "close-in",
    "long-gallery",
    "grenade-pit",
    "sci-fi",
    "qual-v1",
}


class CeaseFire(Exception):
    """The bay is shut down. Nothing else runs."""


def _rso_log(event: str, **fields: Any) -> None:
    record = {"time": paths.now_iso(), "timezone": paths.TZ_LABEL, "event": event}
    record.update(fields)
    path = paths.rso_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def kill_is_set() -> bool:
    return paths.kill_flag().is_file()


def set_kill(reason: str = "range.py kill", actor: str = "range.py") -> None:
    flag = paths.kill_flag()
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text(
        f"RANGE COLD\nset: {paths.now_iso()} ({paths.TZ_LABEL})\n"
        f"reason: {reason}\nactor: {actor}\n",
        encoding="utf-8",
    )
    _rso_log("kill", reason=reason, actor=actor)
    _stop_running_bay()
    wipe_all_bays()


def clear_kill(actor: str = "range.py") -> None:
    flag = paths.kill_flag()
    if flag.is_file():
        flag.unlink()
    _rso_log("unkill", actor=actor)


def _state_path() -> Path:
    folder = paths.state_dir()
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "current-bay.json"


def _write_state(data: dict[str, Any] | None) -> None:
    path = _state_path()
    if data is None:
        path.unlink(missing_ok=True)
        return
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _read_state() -> dict[str, Any] | None:
    path = _state_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def leftover_bays() -> list[Path]:
    found: list[Path] = []
    root = paths.bay_root()
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if child.is_dir() and child.name.startswith("bay-"):
                found.append(child)
    # A crashed session may also have left a pointer behind.
    state = _read_state()
    if state and state.get("bay"):
        pointer = Path(state["bay"])
        if pointer.is_dir() and pointer not in found:
            found.append(pointer)
    return found


def wipe_all_bays() -> list[str]:
    wiped = []
    for bay in leftover_bays():
        armory.wipe_dir(bay)
        wiped.append(str(bay))
    _write_state(None)
    return wiped


def _stop_running_bay() -> None:
    state = _read_state()
    if not state:
        return
    pid = state.get("pid")
    if not pid:
        return
    try:
        os.kill(int(pid), signal.SIGTERM)
        time.sleep(0.2)
        os.kill(int(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, ValueError):
        pass


def drills_today() -> list[dict[str, Any]]:
    today = paths.today_key()
    rows = []
    for row in aar.load_scoreboard():
        when = str(row.get("time") or "")
        if when.startswith(today):
            rows.append(row)
    return rows


def ammo_ok(course_kind: str, n_rounds: int) -> str | None:
    """Return a cease-fire reason, or None if the budget is fine."""
    used = len(drills_today())
    if used >= MAX_DRILLS_PER_DAY:
        return (
            f"Ammo budget spent: {used} drills already today "
            f"(cap {MAX_DRILLS_PER_DAY})."
        )
    if course_kind == "qual":
        if n_rounds < 1 or n_rounds > QUAL_ROUNDS + 5:
            return f"Qual course has {n_rounds} rounds; expected about {QUAL_ROUNDS}."
        return None
    if n_rounds < 1:
        return "Course has no rounds."
    if n_rounds > PRACTICE_MAX:
        return (
            f"Practice course has {n_rounds} rounds; cap is {PRACTICE_MAX} "
            f"({PRACTICE_MIN}–{PRACTICE_MAX})."
        )
    return None


def load_course(name: str) -> dict[str, Any]:
    slug = name.strip().lower()
    aliases = {"qual": "qual-v1", "qualify": "qual-v1", "qualification": "qual-v1"}
    slug = aliases.get(slug, slug)
    path = paths.COURSES / f"{slug}.json"
    if not path.is_file():
        raise CeaseFire(f"Unknown course: {name}")
    try:
        course = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CeaseFire(f"Course {slug} is not valid JSON: {exc}") from exc
    if not isinstance(course, dict) or not course.get("rounds"):
        raise CeaseFire(f"Course {slug} has no rounds.")
    return course


def precheck(course: dict[str, Any]) -> None:
    """Raise CeaseFire if the bay may not open."""
    if kill_is_set():
        raise CeaseFire(
            "Kill switch is set (range/KILL). The owner has to say "
            "`range.py unkill` (or 'range live') before anything runs."
        )
    leftovers = leftover_bays()
    if leftovers:
        raise CeaseFire(
            "Previous bay was not cleaned: "
            + ", ".join(str(p) for p in leftovers)
            + ". Last bot out takes the trash. Run status, then clear."
        )
    try:
        manifest = armory.verify_armory()
    except armory.ArmoryError as exc:
        raise CeaseFire(str(exc)) from exc
    known = armory.known_round_ids(manifest)
    for item in course["rounds"]:
        rid = item.get("id")
        if not rid or rid not in known:
            raise CeaseFire(f"Course names an unknown round id: {rid}")
        lane = item.get("lane")
        if lane not in LANES:
            raise CeaseFire(f"Course names an unknown lane: {lane}")
    reason = ammo_ok(course.get("kind") or "practice", len(course["rounds"]))
    if reason:
        raise CeaseFire(reason)


def _new_bay(drill_id: str) -> Path:
    root = paths.bay_root()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    bay = root / f"bay-{drill_id}"
    if bay.exists():
        armory.wipe_dir(bay)
    bay.mkdir(parents=True, exist_ok=True)
    os.chmod(bay, 0o700)
    (bay / "user").mkdir(exist_ok=True)
    (bay / "rounds").mkdir(exist_ok=True)
    (bay / "runner").mkdir(exist_ok=True)
    (bay / "generated").mkdir(exist_ok=True)
    return bay


def _copy_runner(bay: Path) -> None:
    for name in ("dummy.py", "scoring.py", "grenade.py", "scifi.py"):
        src = paths.CODE_ROOT / name
        dest = bay / "runner" / name
        dest.write_bytes(src.read_bytes())
        os.chmod(dest, 0o700 if name == "dummy.py" else 0o600)


def _plain_hashes(manifest: dict[str, Any], round_ids: list[str]) -> dict[str, str]:
    found = {}
    for entry in manifest.get("rounds") or []:
        if entry.get("id") in round_ids and entry.get("plain_sha256"):
            found[entry["id"]] = entry["plain_sha256"]
    return found


def leftover_plaintexts(plain_hashes: dict[str, str], extra_roots: list[Path] | None = None) -> list[str]:
    """Search known bay roots only. Never walk private/ or the whole disk."""
    hits: list[str] = []
    if not plain_hashes:
        return hits
    wanted = set(plain_hashes.values())
    roots = [paths.bay_root()]
    if extra_roots:
        roots.extend(extra_roots)
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        # Only descend into our own bay directories.
        candidates = []
        if resolved.name.startswith("bay-") and resolved.is_dir():
            candidates = [resolved]
        elif resolved.is_dir():
            candidates = [
                p for p in resolved.iterdir()
                if p.is_dir() and p.name.startswith("bay-")
            ]
        for bay in candidates:
            for dirpath, dirnames, filenames in os.walk(bay, followlinks=False):
                # Do not follow the mirror (it is a defense copy, not checkout).
                dirnames[:] = [d for d in dirnames if d not in {"mirror", "runner"}]
                for name in filenames:
                    path = Path(dirpath) / name
                    try:
                        digest = armory.sha256_file(path)
                    except OSError:
                        continue
                    if digest in wanted:
                        hits.append(str(path))
    return hits


def _bwrap_command(bay: Path, wall_s: int) -> list[str]:
    timeout = shutil.which("timeout")
    prlimit = shutil.which("prlimit")
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise CeaseFire("bubblewrap (bwrap) is not installed. The bay cannot be sealed.")
    inner = [
        bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/sbin", "/sbin",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--bind", str(bay / "mirror"), paths.MIRROR_MOUNT,
        "--bind", str(bay), "/bay",
        "--chdir", "/bay",
        "--setenv", "HOME", "/bay/user",
        "--setenv", "PYTHONPATH", f"/bay/runner:{paths.MIRROR_MOUNT}/defense",
        "--setenv", "TZ", "America/Chicago",
        "--setenv", "RANGE_DEFENSE", f"{paths.MIRROR_MOUNT}/defense",
        "--setenv", "RANGE_MIRROR", paths.MIRROR_MOUNT,
        "--setenv", "INTEGRITY_ROOT", paths.MIRROR_MOUNT,
        "--setenv", "INTEGRITY_CONFIG", f"{paths.MIRROR_MOUNT}/defense/integrity-config.json",
        "--setenv", "INTEGRITY_MANIFEST", f"{paths.MIRROR_MOUNT}/defense/integrity-manifest.json",
        "--setenv", "QUARANTINE_DIR", f"{paths.MIRROR_MOUNT}/defense/quarantine",
        "--unsetenv", "HTTP_PROXY",
        "--unsetenv", "HTTPS_PROXY",
        "--unsetenv", "http_proxy",
        "--unsetenv", "https_proxy",
        "--unsetenv", "ALL_PROXY",
        sys.executable if sys.executable.startswith("/usr/") else "/usr/bin/python3",
        "/bay/runner/dummy.py",
        "--job",
        "/bay/job.json",
        "--out",
        "/bay/results.json",
    ]
    wrapped = inner
    # Do not set RLIMIT_NPROC: it is a per-user cap, and this account
    # already has many processes, so a tight nproc made bwrap fail.
    if prlimit:
        wrapped = [
            prlimit,
            f"--as={MEMORY_BYTES}",
            f"--cpu={wall_s}",
            *wrapped,
        ]
    if timeout:
        wrapped = [timeout, "--kill-after=5", "--signal=TERM", str(wall_s), *wrapped]
    return wrapped


def _write_job(bay: Path, course: dict[str, Any], drill_id: str, manifest: dict[str, Any]) -> None:
    by_id = {e["id"]: e for e in manifest.get("rounds") or []}
    rounds = []
    for item in course["rounds"]:
        entry = by_id[item["id"]]
        rounds.append(
            {
                "id": item["id"],
                "lane": item["lane"],
                "expect": item.get("expect") or "flag",
                "plate": item.get("plate") or "big",
                "filename": entry["filename"],
                "path": f"/bay/rounds/{entry['filename']}",
            }
        )
    job = {
        "drill_id": drill_id,
        "course": course.get("id") or course.get("name"),
        "bay": "/bay",
        "mirror": paths.MIRROR_MOUNT,
        "rounds": rounds,
    }
    (bay / "job.json").write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")


def _empty_summary() -> dict[str, Any]:
    return scoring.summarize([])


def run_session(
    course_name: str,
    kind: str | None = None,
    qual_mode: str | None = None,
    actor: str = "range.py",
    wall_s: int = DEFAULT_WALL_S,
    post_to_board: bool = True,
) -> dict[str, Any]:
    """Full drill flow. Always cleans up. Returns the session record."""
    wall_s = min(max(int(wall_s), 5), HARD_WALL_S)
    course = load_course(course_name)
    if kind:
        course = {**course, "kind": kind}
    course_kind = course.get("kind") or "practice"
    drill_id = paths.now().strftime("%Y%m%d-%H%M%S") + f"-{course.get('id') or course_name}"
    if qual_mode:
        drill_id += f"-{qual_mode}"
    house_before = mirror.snapshot_real_house()
    bay: Path | None = None
    ceased = False
    cease_reason = ""
    results: dict[str, Any] | None = None
    proc: subprocess.Popen[str] | None = None

    try:
        precheck(course)
        bay = _new_bay(drill_id)
        _copy_runner(bay)
        mirror.build_mirror(bay)
        manifest = armory.verify_armory()
        ids = [item["id"] for item in course["rounds"]]
        armory.checkout(ids, bay / "rounds", drill_id=drill_id, actor=actor)
        _write_job(bay, course, drill_id, manifest)
        cmd = _bwrap_command(bay, wall_s)
        _write_state({"drill_id": drill_id, "bay": str(bay), "pid": os.getpid(), "cmd": cmd[:6]})
        _rso_log("start", drill_id=drill_id, course=course.get("id"), wall_s=wall_s, actor=actor)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _write_state({"drill_id": drill_id, "bay": str(bay), "pid": proc.pid})
        try:
            stdout, stderr = proc.communicate(timeout=wall_s + 10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise CeaseFire(f"Sandbox wall-clock cap hit ({wall_s}s).") from None
        if proc.returncode not in {0, None} and not (bay / "results.json").is_file():
            tail = (stderr or stdout or "")[-800:]
            raise CeaseFire(
                f"Sandbox exited {proc.returncode} without results. {tail}"
            )
        if (bay / "results.json").is_file():
            results = json.loads((bay / "results.json").read_text(encoding="utf-8"))
        else:
            raise CeaseFire("Dummy wrote no results.json.")
        (bay / "sandbox.stdout").write_text(stdout or "", encoding="utf-8")
        (bay / "sandbox.stderr").write_text(stderr or "", encoding="utf-8")
    except CeaseFire as exc:
        ceased = True
        cease_reason = str(exc)
        _rso_log("cease-fire", drill_id=drill_id, reason=cease_reason, actor=actor)
    except armory.ArmoryError as exc:
        ceased = True
        cease_reason = f"Armory refused: {exc}"
        _rso_log("cease-fire", drill_id=drill_id, reason=cease_reason, actor=actor)
    except Exception as exc:  # noqa: BLE001
        ceased = True
        cease_reason = f"{type(exc).__name__}: {exc}"
        _rso_log("cease-fire", drill_id=drill_id, reason=cease_reason, actor=actor)
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    summary = (results or {}).get("summary") or _empty_summary()
    rounds = (results or {}).get("rounds") or []
    record: dict[str, Any] = {
        "time": paths.now_iso(),
        "timezone": paths.TZ_LABEL,
        "drill_id": drill_id,
        "course": course.get("id") or course_name,
        "kind": course_kind if not ceased else (course_kind or "drill"),
        "qual_mode": qual_mode,
        "actor": actor,
        "ceased": ceased,
        "cease_reason": cease_reason,
        "summary": summary,
        "rounds": rounds,
    }
    if course_kind == "qual" and not ceased:
        record["rating"] = scoring.qual_rating(
            int(summary.get("correct") or 0),
            int(summary.get("rounds") or 0) or QUAL_ROUNDS,
        )
        record["kind"] = "qual"

    # Post-check: last bot out takes the trash.
    cleanup_notes: list[str] = []
    house_problems = mirror.house_unchanged(house_before)
    if house_problems:
        cleanup_notes.append("REAL HOUSE CHANGED: " + "; ".join(house_problems))
        _rso_log("house-touched", drill_id=drill_id, problems=house_problems)
    # Wipe the bay first, then prove no decrypted rounds remain in bay roots.
    plain = {}
    try:
        plain = _plain_hashes(armory.load_manifest(), [r["id"] for r in course.get("rounds", [])])
    except Exception:
        plain = {}
    if bay is not None:
        armory.wipe_dir(bay)
    leftovers = leftover_bays()
    if leftovers:
        for leftover in leftovers:
            armory.wipe_dir(leftover)
        leftovers = leftover_bays()
        if leftovers:
            cleanup_notes.append("Bay leftover after wipe: " + ", ".join(str(p) for p in leftovers))
    stray = leftover_plaintexts(plain)
    if stray:
        cleanup_notes.append("Decrypted rounds still found: " + ", ".join(stray[:8]))
    try:
        armory.relock(drill_id, actor=actor)
    except Exception as exc:  # noqa: BLE001
        cleanup_notes.append(f"relock failed: {exc}")
    _write_state(None)
    record["cleanup_notes"] = cleanup_notes
    if cleanup_notes and not ceased:
        # A failed cleanup does not rewrite the score, but it does block the next drill.
        _rso_log("cleanup-failed", drill_id=drill_id, notes=cleanup_notes)

    aar.record_session(record)
    aar.write_after_action(record)
    aar.refresh_scoreboard()
    if post_to_board and not ceased:
        aar.append_board_post(aar.board_line_for(record))
    _rso_log(
        "end",
        drill_id=drill_id,
        ceased=ceased,
        points=summary.get("points"),
        correct=summary.get("correct"),
    )
    return record


def format_status() -> str:
    lines = [
        f"Range status at {paths.now_human()}",
        f"- Kill switch: {'SET (RANGE COLD)' if kill_is_set() else 'off'}",
    ]
    if kill_is_set():
        try:
            lines.append(paths.kill_flag().read_text(encoding="utf-8").rstrip())
        except OSError:
            pass
    try:
        manifest = armory.verify_armory()
        lines.append(
            f"- Armory: locked and valid ({manifest.get('round_count')} rounds)"
        )
    except armory.ArmoryError as exc:
        lines.append(f"- Armory: LOCKED / invalid ({exc})")
    leftovers = leftover_bays()
    lines.append(
        "- Previous bay: clean" if not leftovers else f"- Previous bay: LEFTOVER {leftovers}"
    )
    used = drills_today()
    lines.append(
        f"- Ammo today: {len(used)} of {MAX_DRILLS_PER_DAY} drills "
        f"(America/Chicago date {paths.today_key()})"
    )
    rows = aar.load_scoreboard()
    if rows:
        last = rows[-1]
        summary = last.get("summary") or {}
        lines.append(
            f"- Last session: {last.get('time')} {last.get('kind')} "
            f"{last.get('course')} "
            f"{int(summary.get('correct') or 0)}/{int(summary.get('rounds') or 0)}"
        )
    else:
        lines.append("- Last session: none")
    lines.append(f"- Key dir: {paths.key_dir()} (path only; never printed)")
    return "\n".join(lines)
