#!/usr/bin/env python3
"""House defense layer 1: SHA-256 integrity checks for an assistant's own core files.

Commands:
  baseline          Write a fresh manifest of every watched file.
  check             Compare the tree to the manifest. Exit 1 if anything
                    unexpected was added, removed, or changed.
  accept <path>     Approve a legitimate change (or a new/removed file).

Configuration (all optional):
  INTEGRITY_ROOT     the tree to watch (default: the current directory)
  INTEGRITY_CONFIG   a JSON file with "include" (paths relative to the root)
                     and "exclude" (exact paths, "dir/" prefixes, or "*.ext"
                     suffixes). Default: integrity-config.json beside this
                     script if present, else watch README.md only.
  INTEGRITY_MANIFEST where the manifest lives (default: <root>/integrity-manifest.json)

All paths are on this computer only. This tool never phones home and never
touches anyone else's systems.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo(os.environ.get("INTEGRITY_TZ", "America/Chicago"))
CHUNK = 1024 * 1024
HERE = Path(__file__).resolve().parent


def root() -> Path:
    raw = os.environ.get("INTEGRITY_ROOT", "").strip()
    return Path(raw).resolve() if raw else Path.cwd().resolve()


def manifest_path() -> Path:
    raw = os.environ.get("INTEGRITY_MANIFEST", "").strip()
    return Path(raw).resolve() if raw else root() / "integrity-manifest.json"


def _load_config() -> dict:
    raw = os.environ.get("INTEGRITY_CONFIG", "").strip()
    path = Path(raw) if raw else HERE / "integrity-config.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"include": ["README.md"], "exclude": []}


_CONFIG = _load_config()
INCLUDE: list[str] = list(_CONFIG.get("include") or [])
EXCLUDE: list[str] = list(_CONFIG.get("exclude") or [])

# Always excluded, whatever the config says.
EXCLUSION_NOTES = [
    {"what": "__pycache__/ and *.pyc", "why": "Python bytecode caches, rebuilt automatically."},
    {"what": "integrity-manifest.json (any location)", "why": "The baseline itself."},
    {"what": "*.log", "why": "Logs grow in normal use."},
    {"what": "config \"exclude\" entries", "why": "Live state, locks, secrets, and intake folders you list."},
]


def reload_config() -> None:
    """Re-read INTEGRITY_CONFIG (used by tests)."""
    global _CONFIG, INCLUDE, EXCLUDE
    _CONFIG = _load_config()
    INCLUDE = list(_CONFIG.get("include") or [])
    EXCLUDE = list(_CONFIG.get("exclude") or [])


def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def is_excluded(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if "__pycache__" in parts or name.endswith((".pyc", ".pyo")):
        return True
    if name == "integrity-manifest.json" or name.endswith(".log"):
        return True
    for rule in EXCLUDE:
        if rule.startswith("*.") and name.endswith(rule[1:]):
            return True
        if rule.endswith("/") and (rel + "/").startswith(rule):
            return True
        if rel == rule:
            return True
    return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def iter_watched():
    """Yield (absolute Path, posix relative path) for every watched file."""
    for inc in INCLUDE:
        start = root() / inc
        if not start.exists():
            continue
        if start.is_file() or start.is_symlink():
            if not is_excluded(inc):
                yield start, inc
            continue
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            rel_dir = Path(dirpath).relative_to(root()).as_posix()
            dirnames[:] = sorted(
                d for d in dirnames if not is_excluded(f"{rel_dir}/{d}")
            )
            for name in sorted(filenames):
                path = Path(dirpath) / name
                rel = path.relative_to(root()).as_posix()
                if is_excluded(rel):
                    continue
                yield path, rel


def scan() -> dict:
    files = {}
    for path, rel in iter_watched():
        if path.is_symlink():
            files[rel] = {
                "type": "symlink",
                "target": os.readlink(path),
            }
            continue
        if not path.is_file():
            continue
        files[rel] = {
            "type": "file",
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
    return files


def manifest_skeleton(files: dict, created: str | None = None) -> dict:
    return {
        "algorithm": "sha256",
        "root": str(root()),
        "created": created or now_iso(),
        "updated": now_iso(),
        "timezone": "America/Chicago",
        "includes": INCLUDE,
        "exclusions": EXCLUSION_NOTES,
        "file_count": len(files),
        "files": files,
    }


def load_manifest() -> dict:
    if not manifest_path().is_file():
        sys.stderr.write(
            f"No manifest at {manifest_path()}. Run: integrity.py baseline\n"
        )
        sys.exit(2)
    with manifest_path().open(encoding="utf-8") as handle:
        return json.load(handle)


def save_manifest(data: dict) -> None:
    manifest_path().parent.mkdir(parents=True, exist_ok=True)
    data["updated"] = now_iso()
    data["file_count"] = len(data.get("files", {}))
    tmp = manifest_path().with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")
    tmp.replace(manifest_path())


def cmd_baseline() -> int:
    files = scan()
    existing_created = None
    if manifest_path().is_file():
        try:
            existing_created = json.loads(
                manifest_path().read_text(encoding="utf-8")
            ).get("created")
        except (OSError, json.JSONDecodeError):
            existing_created = None
    save_manifest(manifest_skeleton(files, created=existing_created))
    print(f"Baseline written: {manifest_path()}")
    print(f"Watched files: {len(files)}")
    print("Exclusions (not hashed):")
    for note in EXCLUSION_NOTES:
        print(f"  - {note['what']}: {note['why']}")
    return 0


def cmd_check() -> int:
    manifest = load_manifest()
    expected = manifest.get("files", {})
    current = scan()
    added = sorted(set(current) - set(expected))
    removed = sorted(set(expected) - set(current))
    changed = []
    for rel in sorted(set(current) & set(expected)):
        if current[rel] != expected[rel]:
            changed.append(rel)

    if not added and not removed and not changed:
        print(f"Integrity check clean. {len(current)} file(s) match the baseline.")
        return 0

    print("Integrity check FAILED. Unexpected changes:")
    for rel in added:
        print(f"  ADDED    {rel}")
    for rel in removed:
        print(f"  REMOVED  {rel}")
    for rel in changed:
        old = expected[rel]
        new = current[rel]
        detail = []
        if old.get("sha256") and new.get("sha256") and old["sha256"] != new["sha256"]:
            detail.append(f"sha256 {old['sha256'][:12]}… → {new['sha256'][:12]}…")
        if old.get("size") != new.get("size") and "size" in old and "size" in new:
            detail.append(f"size {old['size']} → {new['size']}")
        if old.get("type") != new.get("type"):
            detail.append(f"type {old.get('type')} → {new.get('type')}")
        if old.get("target") != new.get("target") and (
            "target" in old or "target" in new
        ):
            detail.append(f"target {old.get('target')} → {new.get('target')}")
        extra = f" ({', '.join(detail)})" if detail else ""
        print(f"  CHANGED  {rel}{extra}")
    print(
        "If a change is legitimate, approve it with: "
        "integrity.py accept <path>"
    )
    print("Or, after a known-good backup night, rewrite the snapshot with: "
          "integrity.py baseline")
    return 1


def resolve_accept_path(raw: str) -> str:
    path = Path(raw)
    if not path.is_absolute():
        # Try relative to cwd first, then relative to ROOT.
        cwd_candidate = Path.cwd() / path
        root_candidate = root() / path
        if cwd_candidate.exists():
            path = cwd_candidate
        elif root_candidate.exists():
            path = root_candidate
        else:
            path = cwd_candidate
    path = path.resolve()
    try:
        rel = path.relative_to(root().resolve()).as_posix()
    except ValueError:
        sys.stderr.write(f"Path is outside {root()}: {raw}\n")
        sys.exit(2)
    return rel


def cmd_accept(raw_path: str) -> int:
    manifest = load_manifest()
    rel = resolve_accept_path(raw_path)
    if is_excluded(rel):
        sys.stderr.write(
            f"Refusing to accept {rel}: that path is excluded from the baseline.\n"
        )
        return 2
    files = manifest.setdefault("files", {})
    path = root() / rel
    if path.is_symlink() or path.is_file():
        if path.is_symlink():
            entry = {"type": "symlink", "target": os.readlink(path)}
        else:
            entry = {
                "type": "file",
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        action = "updated" if rel in files else "added"
        files[rel] = entry
        save_manifest(manifest)
        print(f"Accepted ({action}): {rel}")
        return 0
    if rel in files:
        del files[rel]
        save_manifest(manifest)
        print(f"Accepted (removed from baseline): {rel}")
        return 0
    sys.stderr.write(f"Nothing to accept: {rel} is not on disk and not in the baseline.\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SHA-256 integrity checks for an assistant's core files (defense only)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline", help="Write a fresh baseline manifest.")
    sub.add_parser("check", help="Report added, removed, or changed files.")
    accept = sub.add_parser("accept", help="Approve a legitimate change.")
    accept.add_argument("path", help="File to approve (added, changed, or removed).")
    args = parser.parse_args(argv)
    if args.cmd == "baseline":
        return cmd_baseline()
    if args.cmd == "check":
        return cmd_check()
    if args.cmd == "accept":
        return cmd_accept(args.path)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
