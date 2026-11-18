#!/usr/bin/env python3
"""Grenade pit: floods, oversized-file pressure, archive listings, storage budget.

Floods are generated in the bay on the fly and never stored in the armory
or synced to Drive. Archive work is metadata-only: listings, never extract.
A zip-bomb-shaped *listing* is a JSON fixture of claimed sizes, not a real
zip bomb and not a working exploit.
"""

from __future__ import annotations

import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

DRIVE_BUDGET = 1 * 1024 * 1024 * 1024  # simulated 1 GB Drive cap
QUARANTINE_CAP = 500 * 1024 * 1024  # matches defense/quarantine.py MAX_SIZE
FLOOD_DEFAULT = 200
# A claimed uncompressed size this far above the compressed size is loud.
RATIO_FLAG = 1000
CLAIMED_TOTAL_FLAG = 100 * 1024 * 1024  # 100 MB claimed from a tiny listing

# Import defense tools only when we are on a tree that has them (the Mirror).
def _defense_dir() -> Path:
    env = os.environ.get("RANGE_DEFENSE")
    if env:
        return Path(env)
    # Inside the sandbox the mirror is /house/defense.
    return Path("/house/defense")


def _load_check_sender():
    defense = _defense_dir()
    if str(defense) not in sys.path:
        sys.path.insert(0, str(defense))
    import check_sender  # noqa: WPS433

    return check_sender


def _load_quarantine():
    defense = _defense_dir()
    if str(defense) not in sys.path:
        sys.path.insert(0, str(defense))
    import quarantine  # noqa: WPS433

    return quarantine


def _fake_email(index: int) -> bytes:
    return (
        f"From: Flood Bot {index} <flood{index}@example.com>\r\n"
        f"To: range-inbox@example.org\r\n"
        f"Subject: junk flood item {index}\r\n"
        f"Date: Tue, 17 Nov 2026 12:00:00 -0600\r\n"
        f"Message-ID: <flood-{index}@example.com>\r\n"
        f"\r\n"
        f"This is inert range junk, item {index}. It is not a real email.\r\n"
    ).encode("utf-8")


def run_flood(bay: Path, count: int = FLOOD_DEFAULT) -> dict[str, Any]:
    """Throw `count` tiny fake emails at check_sender.inspect in-process."""
    check_sender = _load_check_sender()
    folder = bay / "generated" / "flood"
    folder.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    inspected = 0
    flagged = 0
    errors: list[str] = []
    # Cap wall time inside the pit so a hang becomes a clean refuse, not a lock.
    budget_s = 45.0
    for index in range(count):
        if time.monotonic() - started > budget_s:
            errors.append(f"throttled after {inspected} of {count} (time budget)")
            break
        path = folder / f"flood-{index:03d}.eml"
        path.write_bytes(_fake_email(index))
        os.chmod(path, 0o600)
        try:
            msg = check_sender.load_message(str(path))
            result = check_sender.inspect(msg, set(), ())
            inspected += 1
            if result.get("verdict") != "clean":
                flagged += 1
        except Exception as exc:  # noqa: BLE001 — we must catch a tool crash
            errors.append(f"item {index}: {type(exc).__name__}: {exc}")
            if len(errors) >= 5:
                break
    elapsed = time.monotonic() - started
    # Stay steady: finished (or throttled) without a crash storm.
    crashed = bool(errors) and inspected == 0
    refused_cleanly = (inspected + (1 if any("throttled" in e for e in errors) else 0)) > 0 and not crashed
    # Cleanup generated junk inside the bay so we do not keep 200 files longer
    # than this round. The bay itself is wiped at the end of the drill.
    for child in folder.glob("*.eml"):
        child.unlink(missing_ok=True)
    return {
        "kind": "flood",
        "requested": count,
        "inspected": inspected,
        "flagged": flagged,
        "errors": errors,
        "elapsed_s": round(elapsed, 3),
        "crashed": crashed,
        "refused_cleanly": refused_cleanly,
        "flagged_threat": refused_cleanly and not crashed,
        "detail": (
            f"flood inspected {inspected}/{count} in {elapsed:.2f}s, "
            f"errors={len(errors)}"
        ),
    }


def run_sparse_oversize(bay: Path, size: int | None = None) -> dict[str, Any]:
    """Present a sparse file just over the 500 MB quarantine cap. Never fill disk."""
    size = size or (QUARANTINE_CAP + 4096)
    quarantine = _load_quarantine()
    folder = bay / "generated"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "oversize-sparse.bin"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, b"RANGE-SPARSE\n")
        os.ftruncate(fd, size)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    started = time.monotonic()
    crashed = False
    flags: list[str] = []
    report: dict[str, Any] = {}
    try:
        report = quarantine.inspect(path)
        flags = list(report.get("flags") or [])
    except Exception as exc:  # noqa: BLE001
        crashed = True
        flags.append(f"crash: {type(exc).__name__}: {exc}")
    elapsed = time.monotonic() - started
    oversized = any("oversized" in f.lower() or "500" in f for f in flags)
    # Do not leave a huge (even sparse) file sitting around after the check.
    path.unlink(missing_ok=True)
    refused = oversized and not crashed
    return {
        "kind": "sparse_oversize",
        "size": size,
        "flags": flags,
        "elapsed_s": round(elapsed, 3),
        "crashed": crashed,
        "refused_cleanly": refused,
        "flagged_threat": refused,
        "detail": (
            f"sparse {size} bytes, oversized={oversized}, "
            f"flags={len(flags)}, {elapsed:.2f}s"
        ),
        "report_size": report.get("size"),
    }


def list_archive_pressure(listing: dict[str, Any]) -> dict[str, Any]:
    """Flag a zip-bomb-shaped *listing* from metadata only. Never extract."""
    members = listing.get("members") or []
    claimed = 0
    compressed = 0
    flags: list[str] = []
    for member in members:
        name = str(member.get("name") or "")
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
            flags.append(f"path traversal in listing: {name}")
        file_size = int(member.get("file_size") or member.get("uncompressed") or 0)
        compress_size = int(member.get("compress_size") or member.get("compressed") or 0)
        claimed += max(file_size, 0)
        compressed += max(compress_size, 0)
        if compress_size > 0 and file_size >= compress_size * RATIO_FLAG:
            flags.append(
                f"absurd compression ratio on {name}: "
                f"{file_size} claimed from {compress_size}"
            )
    if claimed >= CLAIMED_TOTAL_FLAG:
        flags.append(f"claimed uncompressed total {claimed} bytes is over the flag line")
    if len(members) >= 10000:
        flags.append(f"member count {len(members)} looks like a listing flood")
    refused = bool(flags)
    return {
        "kind": "archive_listing",
        "member_count": len(members),
        "claimed_uncompressed": claimed,
        "compress_total": compressed,
        "flags": flags,
        "crashed": False,
        "refused_cleanly": refused,
        "flagged_threat": refused,
        "detail": f"listing members={len(members)} claimed={claimed} flags={len(flags)}",
    }


def inspect_tiny_zip_metadata(path: Path) -> dict[str, Any]:
    """List a real tiny zip's metadata (infolist only) and run quarantine inspect.

    The zip itself is a handful of small text members, never a bomb. We still
    only use infolist() plus quarantine's own 16-byte head read, and we never
    extract members to disk.
    """
    flags: list[str] = []
    members = []
    crashed = False
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                members.append(
                    {
                        "name": info.filename,
                        "file_size": info.file_size,
                        "compress_size": info.compress_size,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        crashed = True
        flags.append(f"zip list crash: {type(exc).__name__}: {exc}")
    listing = list_archive_pressure({"members": members})
    flags.extend(listing["flags"])
    # Also let the mirror's quarantine look; it reads a 16-byte head only.
    q_flags: list[str] = []
    try:
        quarantine = _load_quarantine()
        report = quarantine.inspect(path)
        q_flags = list(report.get("flags") or [])
    except Exception as exc:  # noqa: BLE001
        crashed = True
        q_flags.append(f"quarantine crash: {type(exc).__name__}: {exc}")
    return {
        "kind": "tiny_zip_metadata",
        "members": members,
        "listing_flags": listing["flags"],
        "quarantine_flags": q_flags,
        "crashed": crashed,
        "refused_cleanly": (not crashed),
        "flagged_threat": (not crashed),  # staying steady is the win on a tiny zip
        "detail": (
            f"tiny zip members={len(members)} listing_flags={len(listing['flags'])} "
            f"quarantine_flags={len(q_flags)}"
        ),
    }


def run_storage_budget(used: int, adding: int, budget: int = DRIVE_BUDGET) -> dict[str, Any]:
    """Refuse an add that would push a simulated 1 GB Drive budget over the line."""
    used = int(used)
    adding = int(adding)
    projected = used + adding
    over = projected > budget
    detail = (
        f"used={used} adding={adding} projected={projected} budget={budget} "
        f"{'REFUSED' if over else 'allowed'}"
    )
    return {
        "kind": "storage_budget",
        "used": used,
        "adding": adding,
        "projected": projected,
        "budget": budget,
        "crashed": False,
        "refused_cleanly": over,
        "flagged_threat": over,
        "detail": detail,
    }


def run_grenade_round(spec: dict[str, Any], bay: Path) -> dict[str, Any]:
    """Dispatch one grenade-pit round from a JSON spec (the decrypted card)."""
    kind = (spec.get("kind") or "").lower()
    if kind == "flood":
        return run_flood(bay, int(spec.get("count") or FLOOD_DEFAULT))
    if kind in {"sparse_oversize", "oversize", "big-file"}:
        size = spec.get("bytes") or spec.get("size")
        return run_sparse_oversize(bay, int(size) if size else None)
    if kind in {"archive_listing", "zip-listing", "zip_listing"}:
        return list_archive_pressure(spec)
    if kind in {"tiny_zip", "tiny-zip"}:
        rel = spec.get("zip_path") or spec.get("path")
        path = Path(rel) if rel else bay / "rounds" / spec.get("filename", "")
        return inspect_tiny_zip_metadata(path)
    if kind in {"storage_budget", "storage", "drive-budget"}:
        return run_storage_budget(
            int(spec.get("used") or 0),
            int(spec.get("adding") or 0),
            int(spec.get("budget") or DRIVE_BUDGET),
        )
    return {
        "kind": kind or "unknown",
        "crashed": False,
        "refused_cleanly": False,
        "flagged_threat": False,
        "detail": f"unknown grenade kind: {kind}",
    }
