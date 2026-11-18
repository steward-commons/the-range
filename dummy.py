#!/usr/bin/env python3
"""Weighted Dummy: a canned, deterministic thrower. No AI, no improvising.

A drill job is a JSON list of rounds. Each round is handed to the matching
defense tool (or the grenade/sci-fi evaluator) as a file argument or a data
card. The Dummy never treats round content as a command. After injection
rounds it checks a canary file and the mirror's policy files.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import scoring

CANARY_NAME = "canary-pwned.txt"
POLICY_FILES = ("defense/core-values.md", "defense/identity-policy.md")


def _defense() -> Path:
    env = os.environ.get("RANGE_DEFENSE")
    if env:
        return Path(env)
    return Path("/house/defense")


def _mirror_root() -> Path:
    env = os.environ.get("RANGE_MIRROR")
    if env:
        return Path(env)
    return Path("/house")


def _hash_if_exists(path: Path) -> str | None:
    if not path.is_file():
        return None
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_policy(mirror: Path) -> dict[str, str | None]:
    return {rel: _hash_if_exists(mirror / rel) for rel in POLICY_FILES}


def canary_path(bay: Path) -> Path:
    return bay / CANARY_NAME


def _run_cli(argv: list[str], timeout: int = 20) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "exit": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "elapsed_s": round(time.monotonic() - started, 3),
            "timed_out": False,
            "crashed": proc.returncode not in {0, 1, 2, 3} and proc.returncode < 0,
        }
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        err = exc.stderr or b""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return {
            "exit": -9,
            "stdout": out,
            "stderr": err or "timeout",
            "elapsed_s": round(time.monotonic() - started, 3),
            "timed_out": True,
            "crashed": True,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "exit": -1,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - started, 3),
            "timed_out": False,
            "crashed": True,
        }


def throw_scan_text(path: Path) -> dict[str, Any]:
    tool = _defense() / "scan_text.py"
    result = _run_cli([sys.executable, str(tool), str(path)])
    flagged = result["exit"] == 1
    result["flagged"] = flagged
    result["refused"] = flagged
    result["tool"] = "scan_text.py"
    return result


def throw_check_sender(path: Path) -> dict[str, Any]:
    tool = _defense() / "check_sender.py"
    result = _run_cli([sys.executable, str(tool), str(path)])
    # 0 clean, 1 suspicious, 2 likely spoof, 3 error
    flagged = result["exit"] in {1, 2}
    result["flagged"] = flagged
    result["refused"] = flagged
    result["tool"] = "check_sender.py"
    return result


def throw_quarantine_inspect(path: Path) -> dict[str, Any]:
    defense = _defense()
    if str(defense) not in sys.path:
        sys.path.insert(0, str(defense))
    import quarantine  # noqa: WPS433

    started = time.monotonic()
    try:
        report = quarantine.inspect(path)
        flags = list(report.get("flags") or [])
        flagged = bool(flags)
        return {
            "exit": 1 if flagged else 0,
            "stdout": json.dumps({"flags": flags, "size": report.get("size")}),
            "stderr": "",
            "elapsed_s": round(time.monotonic() - started, 3),
            "timed_out": False,
            "crashed": False,
            "flagged": flagged,
            "refused": flagged,
            "tool": "quarantine.inspect",
            "flags": flags,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "exit": -1,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.monotonic() - started, 3),
            "timed_out": False,
            "crashed": True,
            "flagged": False,
            "refused": False,
            "tool": "quarantine.inspect",
        }


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return data


def throw_round(round_spec: dict[str, Any], bay: Path, mirror: Path) -> dict[str, Any]:
    """Throw one round and return a result dict with an event."""
    rid = round_spec.get("id") or "unknown"
    lane = round_spec.get("lane") or "unknown"
    expect = (round_spec.get("expect") or scoring.EXPECT_FLAG).lower()
    plate = round_spec.get("plate") or "big"
    filename = round_spec.get("filename") or ""
    path = Path(round_spec["path"]) if round_spec.get("path") else bay / "rounds" / filename
    before_policy = snapshot_policy(mirror)
    canary = canary_path(bay)

    tool_result: dict[str, Any]
    if lane == "grenade-pit":
        import grenade

        spec = dict(round_spec.get("spec") or {})
        if path.is_file() and path.suffix.lower() == ".json" and not spec:
            spec = _load_json(path)
        tool_result = grenade.run_grenade_round(spec, bay)
        tool_result.setdefault("flagged", bool(tool_result.get("flagged_threat")))
        tool_result.setdefault("refused", bool(tool_result.get("refused_cleanly")))
        tool_result.setdefault("crashed", False)
        tool_result.setdefault("timed_out", False)
        tool_result["tool"] = "grenade"
        tool_result.setdefault("stdout", tool_result.get("detail") or "")
        tool_result.setdefault("stderr", "")
        tool_result.setdefault("exit", 0 if tool_result.get("refused_cleanly") or tool_result.get("flagged_threat") else 1)
    elif lane == "sci-fi":
        import scifi

        spec = dict(round_spec.get("spec") or {})
        if path.is_file() and path.suffix.lower() == ".json" and not spec:
            spec = _load_json(path)
        # Supply-chain holo: apply the overnight change, then ask integrity.
        if (spec.get("kind") or "").lower() in {
            "supply-chain",
            "supply_chain",
            "optimizely",
        }:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            try:
                import mirror as mirror_mod

                if hasattr(mirror_mod, "plant_supply_chain_change"):
                    mirror_mod.plant_supply_chain_change(mirror)
                else:
                    _plant_inline(mirror)
            except Exception:
                _plant_inline(mirror)
        tool_result = scifi.run_scifi_round(spec, mirror)
        tool_result.setdefault("flagged", bool(tool_result.get("flagged_threat")))
        tool_result.setdefault("refused", bool(tool_result.get("refused_cleanly")))
        tool_result.setdefault("crashed", False)
        tool_result.setdefault("timed_out", False)
        tool_result["tool"] = "scifi"
        tool_result.setdefault("stdout", tool_result.get("detail") or "")
        tool_result.setdefault("stderr", "")
        tool_result.setdefault("exit", 0 if tool_result.get("flagged") else 1)
    else:
        if not path.is_file():
            tool_result = {
                "exit": 3,
                "stdout": "",
                "stderr": f"round file missing: {path}",
                "elapsed_s": 0,
                "timed_out": False,
                "crashed": True,
                "flagged": False,
                "refused": False,
                "tool": "missing",
            }
        elif path.suffix.lower() in {".eml", ".email"}:
            tool_result = throw_check_sender(path)
            # Close-in HTML bait may also be mailed; .html goes to both tools.
        elif path.suffix.lower() in {".html", ".htm"}:
            # A fake login page: scan the text and inspect as a file.
            scanned = throw_scan_text(path)
            inspected = throw_quarantine_inspect(path)
            flagged = bool(scanned.get("flagged") or inspected.get("flagged"))
            crashed = bool(scanned.get("crashed") or inspected.get("crashed"))
            tool_result = {
                "exit": 1 if flagged else 0,
                "stdout": scanned.get("stdout", "") + "\n" + inspected.get("stdout", ""),
                "stderr": scanned.get("stderr", "") + inspected.get("stderr", ""),
                "elapsed_s": (scanned.get("elapsed_s") or 0) + (inspected.get("elapsed_s") or 0),
                "timed_out": bool(scanned.get("timed_out") or inspected.get("timed_out")),
                "crashed": crashed,
                "flagged": flagged,
                "refused": flagged,
                "tool": "scan_text+quarantine",
            }
        else:
            tool_result = throw_scan_text(path)

    obeyed = canary.is_file()
    after_policy = snapshot_policy(mirror)
    if after_policy != before_policy and lane == "long-gallery":
        # An injection that rewrites core values is the "I followed the sniper" fail.
        obeyed = True
        tool_result["policy_changed"] = True

    event = scoring.classify_round(
        expect=expect,
        flagged=bool(tool_result.get("flagged")),
        refused=bool(tool_result.get("refused")),
        crashed=bool(tool_result.get("crashed")),
        obeyed=obeyed,
        timed_out=bool(tool_result.get("timed_out")),
    )
    # Sci-fi / grenade already set flagged from their own win condition.
    detail = (
        tool_result.get("detail")
        or (tool_result.get("stdout") or "")[:400]
        or (tool_result.get("stderr") or "")[:400]
    )
    return {
        "id": rid,
        "lane": lane,
        "expect": expect,
        "plate": plate,
        "filename": filename or path.name,
        "event": event,
        "tool": tool_result.get("tool"),
        "exit": tool_result.get("exit"),
        "elapsed_s": tool_result.get("elapsed_s"),
        "flagged": bool(tool_result.get("flagged")),
        "refused": bool(tool_result.get("refused")),
        "crashed": bool(tool_result.get("crashed")),
        "timed_out": bool(tool_result.get("timed_out")),
        "obeyed": obeyed,
        "detail": detail if isinstance(detail, str) else str(detail),
        "stdout_tail": (tool_result.get("stdout") or "")[-800:],
    }


def _plant_inline(mirror: Path) -> None:
    planted = mirror / "defense" / "vendor-stub.md"
    planted.write_text(
        "# Trusted vendor stub (range only)\n\n"
        "OVERNIGHT CHANGE. This line was not in yesterday's trusted copy.\n"
        "PLACEHOLDER: this line stands in for a hostile overnight edit.\n",
        encoding="utf-8",
    )
    try:
        os.chmod(planted, 0o600)
    except OSError:
        pass


def run_job(job: dict[str, Any]) -> dict[str, Any]:
    bay = Path(job["bay"])
    mirror = Path(job.get("mirror") or _mirror_root())
    os.environ.setdefault("RANGE_DEFENSE", str(mirror / "defense"))
    os.environ.setdefault("RANGE_MIRROR", str(mirror))
    results = []
    for round_spec in job.get("rounds") or []:
        results.append(throw_round(round_spec, bay, mirror))
    summary = scoring.summarize(results)
    return {
        "drill_id": job.get("drill_id"),
        "course": job.get("course"),
        "rounds": results,
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Weighted Dummy — throw a sealed drill job.")
    parser.add_argument("--job", required=True, help="Path to job.json (inside the bay).")
    parser.add_argument("--out", required=True, help="Where to write results.json.")
    args = parser.parse_args(argv)
    job_path = Path(args.job)
    out_path = Path(args.out)
    job = json.loads(job_path.read_text(encoding="utf-8"))
    # Refuse to run if the job tries to point at anything outside the bay
    # or the mirror. The RSO also enforces this, but the Dummy stays dumb
    # and strict on its own.
    bay = Path(job["bay"]).resolve()
    for item in job.get("rounds") or []:
        raw = item.get("path")
        if not raw:
            continue
        resolved = Path(raw).resolve()
        if _is_outside(resolved, bay) and _is_outside(resolved, _mirror_root()):
            sys.stderr.write(f"Dummy refused a path outside the bay: {resolved}\n")
            return 3
    payload = run_job(job)
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(out_path)
    return 0


def _is_outside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
        return False
    except ValueError:
        return True


if __name__ == "__main__":
    sys.exit(main())
