#!/usr/bin/env python3
"""Encrypted armory: seal, verify, checkout, return, audit.

Fernet (AES-128-CBC + HMAC-SHA256) from the Python cryptography package.
The key lives in ~/.config/steward-range/ (or RANGE_KEY_DIR), never
in this repo, never in a Drive backup, never on a Moot card.

Honest limit: this is defense in depth, not a vault. The range, the key, and
the bot share one account on this box. A stolen armory is still just a pile
of fake phishing emails.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

from cryptography.fernet import Fernet, InvalidToken

import paths

# Extensions and magic the RSO / armory will not seal or check out.
# Macro-enabled Office, scripts, and binaries are never range ammo.
FORBIDDEN_EXTENSIONS = {
    ".py",
    ".pyw",
    ".sh",
    ".bash",
    ".zsh",
    ".csh",
    ".exe",
    ".so",
    ".dll",
    ".dylib",
    ".com",
    ".bat",
    ".cmd",
    ".msi",
    ".scr",
    ".pif",
    ".cpl",
    ".hta",
    ".js",
    ".mjs",
    ".ps1",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".jar",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xltm",
    ".potm",
    ".ppam",
    ".xlam",
}

# Magic-byte families treated as executable. Same idea as quarantine.py.
_EXECUTABLE_MAGIC = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32"),
    (b"#!", "shebang script"),
)


class ArmoryError(Exception):
    """Armory is locked or a checkout was refused."""


def armory_key_path() -> Path:
    return paths.key_dir() / "armory.key"


def hmac_key_path() -> Path:
    return paths.key_dir() / "manifest.hmac"


def manifest_path() -> Path:
    return paths.armory_dir() / "manifest.json"


def _ensure_key_dir() -> Path:
    folder = paths.key_dir()
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    return folder


def _write_secret(path: Path, data: bytes) -> None:
    _ensure_key_dir()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def load_or_create_keys() -> tuple[bytes, bytes]:
    """Return (fernet_key, hmac_key), creating both if they are missing."""
    _ensure_key_dir()
    f_path = armory_key_path()
    h_path = hmac_key_path()
    if f_path.is_file() and h_path.is_file():
        return f_path.read_bytes().strip(), h_path.read_bytes()
    if f_path.is_file() or h_path.is_file():
        raise ArmoryError(
            "Key pair is incomplete. Both armory.key and manifest.hmac must exist."
        )
    f_key = Fernet.generate_key()
    h_key = os.urandom(32)
    _write_secret(f_path, f_key + b"\n")
    _write_secret(h_path, h_key)
    return f_key, h_key


def load_keys() -> tuple[bytes, bytes]:
    f_path = armory_key_path()
    h_path = hmac_key_path()
    if not f_path.is_file() or not h_path.is_file():
        raise ArmoryError(
            f"Armory keys not found in {paths.key_dir()}. "
            "Run: range.py seal"
        )
    # Do not create keys on a read. Checkout should fail closed.
    mode_f = f_path.stat().st_mode
    mode_h = h_path.stat().st_mode
    if mode_f & 0o077:
        raise ArmoryError(f"{f_path} is not mode 600; refusing to use it.")
    if mode_h & 0o077:
        raise ArmoryError(f"{h_path} is not mode 600; refusing to use it.")
    return f_path.read_bytes().strip(), h_path.read_bytes()


def _canonical_body(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: dict[str, Any], hmac_key: bytes) -> str:
    return hmac.new(hmac_key, _canonical_body(manifest), hashlib.sha256).hexdigest()


def verify_signature(manifest: dict[str, Any], hmac_key: bytes) -> bool:
    sig = manifest.get("signature") or ""
    expected = sign_manifest(manifest, hmac_key)
    return hmac.compare_digest(str(sig), expected)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sniff_forbidden(path: Path) -> str | None:
    """Return a reason if this file must not enter the armory, else None."""
    suffix = path.suffix.lower()
    if suffix in FORBIDDEN_EXTENSIONS:
        return f"forbidden extension {suffix}"
    # Compound suffixes like file.tar.sh are already caught by .sh.
    name = path.name.lower()
    if name.endswith(".py") or name.endswith(".sh"):
        return "forbidden script name"
    try:
        with path.open("rb") as handle:
            head = handle.read(16)
    except OSError as exc:
        return f"could not read: {exc}"
    for magic, label in _EXECUTABLE_MAGIC:
        if head.startswith(magic):
            return f"executable content ({label})"
    if path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return "executable bit is set"
    return None


def _iter_source_files(root: Path | None = None) -> list[Path]:
    root = root or paths.SOURCE_ROUNDS
    files: list[Path] = []
    if not root.is_dir():
        return files
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            path = Path(dirpath) / name
            if path.is_file():
                files.append(path)
    return files


def round_id_for(path: Path, source_root: Path | None = None) -> str:
    source_root = source_root or paths.SOURCE_ROUNDS
    rel = path.relative_to(source_root).as_posix()
    # ci-01-lookalike.eml -> ci-01
    stem = Path(rel).name
    parts = stem.split("-")
    if len(parts) >= 2 and parts[1][:1].isdigit():
        return f"{parts[0]}-{parts[1].split('.')[0]}"
    return Path(stem).stem


def lane_for(path: Path, source_root: Path | None = None) -> str:
    source_root = source_root or paths.SOURCE_ROUNDS
    rel = path.relative_to(source_root)
    return rel.parts[0] if len(rel.parts) > 1 else "misc"


def ciphertext_path(round_id: str) -> Path:
    return paths.armory_dir() / f"{round_id}.fernet"


def _secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def audit(event: str, **fields: Any) -> None:
    record = {"time": paths.now_iso(), "timezone": paths.TZ_LABEL, "event": event}
    record.update(fields)
    log = paths.armory_audit_path()
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def seal_sources(
    source_root: Path | None = None,
    actor: str = "range.py",
) -> dict[str, Any]:
    """Encrypt every source round and write a signed manifest."""
    source_root = source_root or paths.SOURCE_ROUNDS
    files = _iter_source_files(source_root)
    if not files:
        raise ArmoryError(f"No source rounds under {source_root}")

    f_key, h_key = load_or_create_keys()
    box = Fernet(f_key)
    _secure_dir(paths.armory_dir())

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in files:
        reason = sniff_forbidden(path)
        if reason:
            raise ArmoryError(f"Refusing to seal {path.name}: {reason}")
        rid = round_id_for(path, source_root)
        if rid in seen:
            raise ArmoryError(f"Duplicate round id {rid} ({path})")
        seen.add(rid)
        plaintext = path.read_bytes()
        token = box.encrypt(plaintext)
        dest = ciphertext_path(rid)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token)
        finally:
            os.close(fd)
        os.chmod(dest, 0o600)
        entries.append(
            {
                "id": rid,
                "lane": lane_for(path, source_root),
                "source": path.relative_to(source_root).as_posix(),
                "filename": path.name,
                "media": path.suffix.lower().lstrip(".") or "txt",
                "sha256": sha256_bytes(token),
                "size": len(token),
                "plain_sha256": sha256_bytes(plaintext),
                "plain_size": len(plaintext),
            }
        )

    manifest: dict[str, Any] = {
        "version": 1,
        "algorithm": "fernet",
        "signed_with": "HMAC-SHA256",
        "created": paths.now_iso(),
        "timezone": paths.TZ_LABEL,
        "round_count": len(entries),
        "rounds": entries,
    }
    manifest["signature"] = sign_manifest(manifest, h_key)
    dest = manifest_path()
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(dest)
    os.chmod(dest, 0o600)
    audit(
        "seal",
        actor=actor,
        round_count=len(entries),
        round_ids=[e["id"] for e in entries],
    )
    return manifest


def load_manifest() -> dict[str, Any]:
    path = manifest_path()
    if not path.is_file():
        raise ArmoryError(f"No armory manifest at {path}. Run: range.py seal")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ArmoryError(f"Armory manifest is not valid JSON: {exc}") from exc


def verify_armory() -> dict[str, Any]:
    """Check the signature and every ciphertext hash. Fail closed."""
    try:
        _f_key, h_key = load_keys()
    except ArmoryError:
        raise
    manifest = load_manifest()
    if not verify_signature(manifest, h_key):
        raise ArmoryError(
            "Armory manifest signature mismatch. Armory stays locked."
        )
    missing = []
    mismatched = []
    for entry in manifest.get("rounds", []):
        rid = entry.get("id")
        path = ciphertext_path(str(rid))
        if not path.is_file():
            missing.append(str(rid))
            continue
        digest = sha256_file(path)
        if digest != entry.get("sha256"):
            mismatched.append(str(rid))
        size = path.stat().st_size
        if entry.get("size") is not None and size != entry["size"]:
            mismatched.append(str(rid))
    if missing or mismatched:
        raise ArmoryError(
            "Armory integrity check failed (stays locked): "
            f"missing={missing or 'none'} mismatched={mismatched or 'none'}"
        )
    return manifest


def lookup_round(manifest: dict[str, Any], round_id: str) -> dict[str, Any]:
    for entry in manifest.get("rounds", []):
        if entry.get("id") == round_id:
            return entry
    raise ArmoryError(f"Unknown round id: {round_id}")


def checkout(
    round_ids: Iterable[str],
    dest_dir: Path,
    drill_id: str,
    actor: str = "range.py",
) -> list[Path]:
    """Decrypt only the named rounds into dest_dir (mode 700)."""
    manifest = verify_armory()
    f_key, _h_key = load_keys()
    box = Fernet(f_key)
    _secure_dir(dest_dir)
    written: list[Path] = []
    hashes: list[dict[str, str]] = []
    wanted = list(round_ids)
    try:
        for rid in wanted:
            entry = lookup_round(manifest, rid)
            token_path = ciphertext_path(rid)
            token = token_path.read_bytes()
            if sha256_bytes(token) != entry["sha256"]:
                raise ArmoryError(f"Ciphertext hash mismatch on checkout: {rid}")
            reason = None
            try:
                plaintext = box.decrypt(token)
            except InvalidToken as exc:
                raise ArmoryError(f"Decrypt failed for {rid}") from exc
            if sha256_bytes(plaintext) != entry.get("plain_sha256"):
                raise ArmoryError(f"Plaintext hash mismatch on checkout: {rid}")
            # Re-check the decrypted bytes the same way as intake.
            out = dest_dir / entry["filename"]
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, plaintext)
            finally:
                os.close(fd)
            os.chmod(out, 0o600)
            reason = sniff_forbidden(out)
            if reason:
                out.unlink(missing_ok=True)
                raise ArmoryError(f"Round {rid} failed the executable check: {reason}")
            written.append(out)
            hashes.append(
                {
                    "id": rid,
                    "filename": entry["filename"],
                    "plain_sha256": entry.get("plain_sha256", ""),
                    "cipher_sha256": entry["sha256"],
                }
            )
    except Exception:
        # Leave no half-decrypted checkout behind.
        for path in written:
            path.unlink(missing_ok=True)
        raise
    audit(
        "checkout",
        actor=actor,
        drill_id=drill_id,
        round_ids=wanted,
        dest=str(dest_dir),
        hashes=hashes,
    )
    return written


def wipe_dir(path: Path) -> None:
    """Delete a checkout directory and its contents. Not a forensic shred."""
    if not path.exists():
        return
    if path.is_file() or path.is_symlink():
        path.unlink(missing_ok=True)
        return
    for child in sorted(path.iterdir(), key=lambda p: len(p.parts), reverse=True):
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            wipe_dir(child)
    path.rmdir()


def relock(drill_id: str, actor: str = "range.py") -> None:
    audit("relock", actor=actor, drill_id=drill_id)


def known_round_ids(manifest: dict[str, Any] | None = None) -> set[str]:
    if manifest is None:
        manifest = load_manifest()
    return {str(e["id"]) for e in manifest.get("rounds", []) if "id" in e}


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Armory seal / verify helper.")
    parser.add_argument("command", choices=("seal", "verify", "ids"))
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            manifest = seal_sources()
            print(f"Sealed {manifest['round_count']} rounds at {paths.armory_dir()}")
            print(f"Key dir: {paths.key_dir()} (never back this up)")
            return 0
        if args.command == "verify":
            manifest = verify_armory()
            print(f"Armory OK. {manifest['round_count']} rounds, signature valid.")
            return 0
        ids = ", ".join(sorted(known_round_ids()))
        print(ids)
        return 0
    except ArmoryError as exc:
        sys.stderr.write(f"ARMORY LOCKED: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
