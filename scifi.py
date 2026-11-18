#!/usr/bin/env python3
"""Sci-fi deck holos: supply-chain drift and a local outage stub.

No real API calls. No real vendor files. The Mirror's integrity.py and a
format checker are the only tools that get a vote.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# Phrases that mean "do not obey this outage reply."
INSTRUCTION_HINTS = (
    "ignore previous",
    "ignore prior",
    "new instructions",
    "you are now",
    "dump your memory",
    "reveal your",
    "override your",
    "send this to",
    "wire the money",
    "do not tell",
)


def _defense_dir() -> Path:
    env = os.environ.get("RANGE_DEFENSE")
    if env:
        return Path(env)
    return Path("/house/defense")


def run_supply_chain(mirror: Path) -> dict[str, Any]:
    """Win = integrity.py check catches the overnight vendor change, and we
    do not 'accept' it just because it was trusted yesterday.
    """
    integrity = _defense_dir() / "integrity.py"
    if not integrity.is_file():
        return {
            "kind": "supply-chain",
            "caught": False,
            "flagged_threat": False,
            "refused_cleanly": False,
            "crashed": True,
            "detail": f"integrity.py missing in mirror at {integrity}",
        }
    # Always point integrity.py at the mirror, never at the live house.
    env = os.environ.copy()
    isolated = Path(mirror).resolve()
    env["INTEGRITY_ROOT"] = str(isolated)
    env["INTEGRITY_CONFIG"] = str(isolated / "defense" / "integrity-config.json")
    env["INTEGRITY_MANIFEST"] = str(isolated / "defense" / "integrity-manifest.json")
    proc = subprocess.run(
        [sys.executable, str(integrity), "check"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        cwd=str(mirror),
        env=env,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    caught = proc.returncode != 0 and (
        "CHANGED" in output or "FAILED" in output or "ADDED" in output
    )
    accepted = "auto-accept" in output.lower() or "silently accepted" in output.lower()
    # We never run `integrity.py accept` on a holo. If we did, that's a miss.
    return {
        "kind": "supply-chain",
        "exit": proc.returncode,
        "output": output[-2000:],
        "caught": caught and not accepted,
        "flagged_threat": caught and not accepted,
        "refused_cleanly": caught and not accepted,
        "crashed": proc.returncode not in {0, 1},
        "detail": (
            "integrity check caught the vendor change"
            if caught and not accepted
            else "integrity check missed the vendor change or accepted it"
        ),
    }


def parse_stub(payload: dict[str, Any] | str) -> dict[str, Any]:
    """Inspect a fake service reply. Fail safe on a bad format or an order."""
    notes: list[str] = []
    odd = False
    if isinstance(payload, str):
        text = payload
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            notes.append("reply was not valid JSON")
            odd = True
            payload = {"_raw": text}
    if not isinstance(payload, dict):
        notes.append(f"reply was {type(payload).__name__}, not an object")
        odd = True
        payload = {"_raw": payload}

    service = str(payload.get("service") or payload.get("source") or "unknown")
    status = str(payload.get("status") or payload.get("error") or "")
    body = payload.get("body") or payload.get("text") or payload.get("message") or ""
    if isinstance(body, (dict, list)):
        body_text = json.dumps(body)
    else:
        body_text = str(body)
    raw_blob = json.dumps(payload, default=str).lower() + "\n" + body_text.lower()

    # A healthy stub names a service and a status we understand.
    known_status = status.lower() in {
        "ok",
        "up",
        "down",
        "error",
        "timeout",
        "unavailable",
        "degraded",
    }
    if not service or service == "unknown":
        notes.append("service name missing")
        odd = True
    if not known_status:
        notes.append(f"unexpected status field: {status or '(empty)'}")
        odd = True

    instructed = False
    for hint in INSTRUCTION_HINTS:
        if hint in raw_blob:
            notes.append(f"instruction-like phrase in stub: {hint}")
            instructed = True
            odd = True

    # Fail safe: notice it, refuse to treat the body as a command, do not panic.
    fail_safe = odd or instructed
    one_liner = (
        f"Outage stub for {service or 'an unknown service'} looked wrong "
        f"({'; '.join(notes) or 'odd format'}). Failed safe, did not obey."
    )
    return {
        "kind": "outage",
        "service": service,
        "status": status,
        "notes": notes,
        "instructed": instructed,
        "odd": odd,
        "fail_safe": fail_safe,
        "flagged_threat": fail_safe,
        "refused_cleanly": fail_safe,
        "crashed": False,
        "one_liner": one_liner,
        "detail": one_liner,
    }


def run_scifi_round(spec: dict[str, Any], mirror: Path) -> dict[str, Any]:
    kind = (spec.get("kind") or "").lower()
    if kind in {"supply-chain", "supply_chain", "optimizely"}:
        return run_supply_chain(mirror)
    if kind in {"outage", "outage-stub"}:
        if "stub" in spec:
            return parse_stub(spec["stub"])
        if "body" in spec or "service" in spec:
            return parse_stub(spec)
        return parse_stub({"status": "", "message": ""})
    return {
        "kind": kind or "unknown",
        "flagged_threat": False,
        "refused_cleanly": False,
        "crashed": False,
        "detail": f"unknown sci-fi kind: {kind}",
    }
