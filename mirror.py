#!/usr/bin/env python3
"""Build a per-session Mirror: a copy of defense/ for sparring only.

The real house is never mounted inside the bay. Inside the sandbox the
mirror is bound at paths.MIRROR_MOUNT (/house) and the defense tools are
pointed at it with environment variables. Logs the copy writes are thrown away with the bay.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import paths

def _real_defense() -> Path:
    """The house's real defense/ folder (read-only source for each Mirror)."""
    return paths.house_root() / "defense"

# Never copy these out of the real house and into a bay.
SKIP_NAMES = {
    "__pycache__",
    "integrity-manifest.json",
}
SKIP_SUFFIXES = {".pyc", ".pyo"}
# Live logs get a stub header in the copy, not the real entries.
STUB_LOGS = {
    "injection-log.md",
    "impersonation-log.md",
    "growth-log.md",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_real_house() -> dict[str, dict[str, int | str]]:
    """Hash the real defense programs and policy files (not logs, not quarantine)."""
    files: dict[str, dict[str, int | str]] = {}
    if not _real_defense().is_dir():
        return files
    for path in sorted(_real_defense().iterdir()):
        if not path.is_file():
            continue
        if path.name in STUB_LOGS or path.name == "integrity-manifest.json":
            continue
        if path.suffix in SKIP_SUFFIXES:
            continue
        rel = f"defense/{path.name}"
        files[rel] = {"sha256": _sha256_file(path), "size": path.stat().st_size}
    return files


def house_unchanged(before: dict[str, dict[str, int | str]]) -> list[str]:
    after = snapshot_real_house()
    problems = []
    for rel in sorted(set(before) | set(after)):
        if rel not in before:
            problems.append(f"ADDED {rel}")
        elif rel not in after:
            problems.append(f"REMOVED {rel}")
        elif before[rel] != after[rel]:
            problems.append(f"CHANGED {rel}")
    return problems


def _copy_file(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    # Drop execute bits on data files; keep them on the defense scripts
    # so the CLI can still be invoked inside the bay.
    if src.suffix == ".py":
        mode = dest.stat().st_mode
        os.chmod(dest, mode | stat.S_IXUSR)
    else:
        os.chmod(dest, 0o600)


def _stub_log(dest: Path, title: str, blurb: str) -> None:
    dest.write_text(
        f"# {title}\n\n"
        f"{blurb}\n\n"
        "This is a Mirror copy for a range drill. Entries written here are "
        "thrown away with the bay and never touch the real house log.\n",
        encoding="utf-8",
    )
    os.chmod(dest, 0o600)


def _write_scratch_manifest(mirror_root: Path, planted: list[Path]) -> None:
    """Write an integrity baseline that matches only what the mirror contains."""
    files: dict[str, dict] = {}
    # integrity.py walks INCLUDE under the mirror root. We only place
    # README.md and defense/ in the mirror, so the scan will see just those.
    for path in [mirror_root / "README.md", *sorted((mirror_root / "defense").glob("*"))]:
        if not path.is_file():
            continue
        if path.name == "integrity-manifest.json":
            continue
        if path.suffix in SKIP_SUFFIXES:
            continue
        rel = path.relative_to(mirror_root).as_posix()
        files[rel] = {
            "type": "file",
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        }
    manifest = {
        "algorithm": "sha256",
        "root": paths.MIRROR_MOUNT,
        "created": paths.now_iso(),
        "updated": paths.now_iso(),
        "timezone": paths.TZ_LABEL,
        "includes": ["README.md", "defense"],
        "exclusions": [
            {
                "what": "range mirror scratch baseline",
                "why": "This manifest exists only inside a drill bay.",
            }
        ],
        "file_count": len(files),
        "files": files,
        "range_planted": [p.relative_to(mirror_root).as_posix() for p in planted],
    }
    config = mirror_root / "defense" / "integrity-config.json"
    config.write_text(
        json.dumps({"include": ["README.md", "defense"],
                    "exclude": ["defense/quarantine/", "defense/integrity-config.json"]}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
    dest = mirror_root / "defense" / "integrity-manifest.json"
    dest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.chmod(dest, 0o600)


def build_mirror(bay: Path) -> Path:
    """Create bay/mirror with a copy of defense/ and a stub README.

    Returns the mirror root (bind this at paths.MIRROR_MOUNT inside bwrap).
    """
    mirror = bay / "mirror"
    if mirror.exists():
        shutil.rmtree(mirror)
    defense_dest = mirror / "defense"
    defense_dest.mkdir(parents=True, exist_ok=True)
    os.chmod(mirror, 0o700)
    os.chmod(defense_dest, 0o700)

    if not _real_defense().is_dir():
        raise FileNotFoundError(f"Real defense tree missing: {_real_defense()}")

    for path in sorted(_real_defense().iterdir()):
        if path.name in SKIP_NAMES or path.suffix in SKIP_SUFFIXES:
            continue
        if path.is_dir():
            if path.name == "quarantine":
                # Empty quarantine folder for the copy; never copy real intake.
                q = defense_dest / "quarantine"
                q.mkdir(exist_ok=True)
                os.chmod(q, 0o700)
                (q / ".keep").write_text("mirror quarantine (empty)\n", encoding="utf-8")
            continue
        if not path.is_file():
            continue
        dest = defense_dest / path.name
        if path.name in STUB_LOGS:
            title = path.name.replace("-", " ").replace(".md", "").title()
            _stub_log(dest, title, "Range-local stub; the real log was not copied.")
            continue
        _copy_file(path, dest)

    readme = mirror / "README.md"
    readme.write_text(
        "Range Mirror (session copy). This is not the real house.\n",
        encoding="utf-8",
    )
    os.chmod(readme, 0o600)

    # A planted "trusted vendor" file for the supply-chain holo. The
    # baseline is taken *after* this is written, then the sci-fi drill
    # changes it "overnight."
    planted = defense_dest / "vendor-stub.md"
    planted.write_text(
        "# Trusted vendor stub (range only)\n\n"
        "This file is a stand-in for a shared vendor artifact. It starts "
        "clean and is part of the mirror baseline. It is not a real skill "
        "and is not installed on the real house.\n",
        encoding="utf-8",
    )
    os.chmod(planted, 0o600)

    _write_scratch_manifest(mirror, [planted])
    return mirror


def plant_supply_chain_change(mirror: Path) -> Path:
    """Quietly change the planted vendor file after the baseline is written."""
    planted = mirror / "defense" / "vendor-stub.md"
    planted.write_text(
        "# Trusted vendor stub (range only)\n\n"
        "OVERNIGHT CHANGE. This line was not in yesterday's trusted copy.\n"
        "PLACEHOLDER: this line stands in for a hostile overnight edit.\n",
        encoding="utf-8",
    )
    os.chmod(planted, 0o600)
    return planted
