#!/usr/bin/env python3
"""House defense layer 1: quarantine untrusted downloads on this computer.

Commands:
  intake <file>              Move a file into quarantine and inspect it.
  release <file> <dest>      Move it out only if it is clean, or with --override.
  list                       Show what is currently in quarantine.
  show <file>                Print the recorded inspection for one item.

Inspection is read-only. This tool never executes quarantined content,
never extracts archives to disk, and never attacks any other system.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/Chicago")
DEFENSE = Path(__file__).resolve().parent
QUARANTINE = Path(os.environ.get("QUARANTINE_DIR") or (DEFENSE / "quarantine"))
INDEX_PATH = QUARANTINE / "INDEX.json"
CHUNK = 1024 * 1024
MAX_SIZE = 500 * 1024 * 1024  # 500 MB
HEAD_BYTES = 8192

# Extensions that often mean "run me" or "I may contain a payload."
DANGEROUS_EXT = {
    "sh", "bash", "zsh", "csh", "ksh", "fish",
    "exe", "com", "bat", "cmd", "ps1", "msi", "scr", "pif", "hta", "cpl",
    "dll", "so", "dylib", "sys",
    "py", "pyw", "pyc", "pyo",
    "js", "mjs", "cjs", "vbs", "vbe", "wsf", "wsh", "jse",
    "jar", "class", "war",
    "php", "pl", "rb", "lua",
    "docm", "xlsm", "pptm", "dotm", "xltm", "ppsm",
}

# Extensions people try to spoof so a file looks harmless.
SAFE_LOOKING_EXT = {
    "pdf", "jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff",
    "txt", "md", "csv", "rtf",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "mp3", "mp4", "wav", "webm", "mov", "ogg",
}

# What we expect a given extension's content family to be.
# If we detect a concrete family that is not in this set, flag a mismatch.
EXT_FAMILIES = {
    "pdf": {"pdf"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "webp": {"webp"},
    "bmp": {"bmp"},
    "tif": {"tiff"},
    "tiff": {"tiff"},
    "zip": {"zip"},
    "jar": {"zip"},
    "docx": {"zip"},
    "xlsx": {"zip"},
    "pptx": {"zip"},
    "odt": {"zip"},
    "ods": {"zip"},
    "odp": {"zip"},
    "epub": {"zip"},
    "gz": {"gzip"},
    "tgz": {"gzip"},
    "bz2": {"bzip2"},
    "xz": {"xz"},
    "7z": {"7z"},
    "rar": {"rar"},
    "tar": {"tar"},
    "mp4": {"mp4"},
    "m4a": {"mp4"},
    "mov": {"mp4"},
    "webm": {"webm", "matroska"},
    "mkv": {"matroska", "webm"},
    "mp3": {"mp3"},
    "wav": {"wav"},
    "ogg": {"ogg"},
    "flac": {"flac"},
    "exe": {"pe"},
    "dll": {"pe"},
    "so": {"elf"},
    "dylib": {"macho"},
    "sh": {"shell", "script", "text"},
    "bash": {"shell", "script", "text"},
    "py": {"python", "script", "text", "empty"},
    "js": {"javascript", "script", "text", "empty"},
    "json": {"json", "text", "empty"},
    "md": {"text", "empty"},
    "txt": {"text", "empty"},
    "csv": {"text", "empty"},
    "html": {"html", "text"},
    "htm": {"html", "text"},
    "xml": {"xml", "text"},
    "svg": {"xml", "text"},
}

EXECUTABLE_FAMILIES = {"elf", "pe", "macho", "shell", "python", "javascript", "script"}


def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def now_human() -> str:
    return datetime.now(TZ).strftime("%Y-%m-%d %-I:%M %p") + " (America/Chicago)"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def extensions_of(name: str) -> list[str]:
    """Return suffixes in order, skipping a leading dot on hidden names."""
    parts = Path(name).name.split(".")
    if parts and parts[0] == "":
        parts = parts[1:]
    if len(parts) <= 1:
        return []
    return [p.lower() for p in parts[1:]]


def sniff_with_file_cmd(path: Path) -> tuple[str, str] | None:
    file_bin = shutil.which("file")
    if not file_bin:
        return None
    try:
        import subprocess

        brief = subprocess.run(
            [file_bin, "--brief", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        mime = subprocess.run(
            [file_bin, "--brief", "--mime-type", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if brief.returncode != 0:
            return None
        label = (brief.stdout or "").strip() or "data"
        mime_type = (mime.stdout or "").strip()
        family = family_from_mime(mime_type, label)
        if mime_type:
            label = f"{label} [{mime_type}]"
        return label, family
    except OSError:
        return None


def family_from_mime(mime: str, label: str) -> str:
    mime = (mime or "").lower()
    mapping = {
        "application/pdf": "pdf",
        "application/x-pdf": "pdf",
        "image/png": "png",
        "image/jpeg": "jpeg",
        "image/gif": "gif",
        "image/webp": "webp",
        "image/bmp": "bmp",
        "image/tiff": "tiff",
        "application/zip": "zip",
        "application/gzip": "gzip",
        "application/x-gzip": "gzip",
        "application/x-bzip2": "bzip2",
        "application/x-xz": "xz",
        "application/x-7z-compressed": "7z",
        "application/x-rar-compressed": "rar",
        "application/x-tar": "tar",
        "application/x-executable": "elf",
        "application/x-sharedlib": "elf",
        "application/x-elf": "elf",
        "application/x-dosexec": "pe",
        "application/vnd.microsoft.portable-executable": "pe",
        "text/x-shellscript": "shell",
        "text/x-python": "python",
        "text/x-script.python": "python",
        "application/json": "json",
        "text/plain": "text",
        "text/html": "html",
        "text/xml": "xml",
        "application/xml": "xml",
        "video/mp4": "mp4",
        "video/webm": "webm",
        "audio/mpeg": "mp3",
        "audio/wav": "wav",
        "application/octet-stream": "unknown",
    }
    if mime in mapping:
        return mapping[mime]
    if mime.startswith("text/"):
        lower = label.lower()
        if "python" in lower:
            return "python"
        if "shell" in lower or "sh script" in lower:
            return "shell"
        return "text"
    return "unknown"


def _is_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    sample = data[:HEAD_BYTES]
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def sniff_bytes(path: Path) -> tuple[str, str]:
    size = path.stat().st_size
    if size == 0:
        return "empty", "empty"
    with path.open("rb") as handle:
        data = handle.read(HEAD_BYTES)
    if data.startswith(b"\x7fELF"):
        return "ELF executable or shared object", "elf"
    if data.startswith(b"MZ"):
        return "DOS/Windows executable (MZ/PE)", "pe"
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe")):
        return "Mach-O executable", "macho"
    if data.startswith(b"%PDF"):
        return "PDF document", "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image", "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image", "jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF image", "gif"
    if data.startswith(b"BM"):
        return "BMP image", "bmp"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "WEBP image", "webp"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "WAV audio", "wav"
    if data.startswith(b"fLaC"):
        return "FLAC audio", "flac"
    if data.startswith(b"OggS"):
        return "Ogg container", "ogg"
    if data.startswith(b"ID3") or data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "MP3 audio", "mp3"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "MP4/ISO media", "mp4"
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return "Matroska/WebM media", "matroska"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "ZIP archive", "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip compressed data", "gzip"
    if data.startswith(b"BZh"):
        return "bzip2 compressed data", "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz compressed data", "xz"
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z archive", "7z"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR archive", "rar"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar archive", "tar"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE compound document (may contain macros)", "ole"
    if data.startswith(b"#!"):
        first = data.split(b"\n", 1)[0].decode("ascii", "replace").strip()
        lower = first.lower()
        if "python" in lower:
            return f"Python script ({first})", "python"
        if any(token in lower for token in ("/sh", "bash", "zsh", "dash", "ksh", "fish")):
            return f"shell script ({first})", "shell"
        return f"script ({first})", "script"
    if data.lstrip().startswith((b"<?xml", b"\xef\xbb\xbf<?xml")):
        return "XML text", "xml"
    if data.lstrip()[:1] in (b"<",) and b"<html" in data.lower() or data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return "HTML text", "html"
    if _is_text(data):
        stripped = data.lstrip()
        if stripped.startswith((b"{", b"[")):
            return "JSON or JSON-like text", "json"
        return "UTF-8/ASCII text", "text"
    return "data", "unknown"


def sniff(path: Path) -> tuple[str, str]:
    probed = sniff_with_file_cmd(path)
    if probed:
        return probed
    return sniff_bytes(path)


def load_index() -> dict:
    if not INDEX_PATH.is_file():
        return {"items": {}}
    with INDEX_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("items", {})
    return data


def save_index(data: dict) -> None:
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_PATH.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    tmp.replace(INDEX_PATH)


def unique_dest(directory: Path, name: str) -> Path:
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem = Path(name).name
    for i in range(1, 1000):
        candidate = directory / f"{stem}.q{i}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find a free name in {directory} for {name}")


def has_executable_bits(path: Path) -> bool:
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def looks_like_path_traversal(name: str) -> bool:
    if name.startswith(("/", "\\")):
        return True
    if len(name) >= 2 and name[1] == ":":
        return True
    parts = Path(name.replace("\\", "/")).parts
    return ".." in parts


def dangerous_name(name: str) -> bool:
    ext = extensions_of(name)
    last = ext[-1] if ext else Path(name).suffix.lower().lstrip(".")
    if last in DANGEROUS_EXT:
        return True
    base = Path(name).name.lower()
    return base == "vbaproject.bin" or base.endswith("/vbaproject.bin")


def inspect_zip(path: Path) -> list[str]:
    flags = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                name = info.filename
                if looks_like_path_traversal(name):
                    flags.append(f"archive path traversal: {name}")
                if info.is_dir():
                    continue
                if dangerous_name(name) or Path(name).name.lower() == "vbaproject.bin":
                    flags.append(f"archive contains executable, script, or macro: {name}")
                try:
                    with archive.open(info, "r") as handle:
                        head = handle.read(16)
                    family = classify_head(head)
                    if family in EXECUTABLE_FAMILIES:
                        flags.append(f"archive contains {family} content: {name}")
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    # Encrypted or unreadable member: note it, do not extract.
                    if info.flag_bits & 0x1:
                        flags.append(f"archive has encrypted member: {name}")
    except zipfile.BadZipFile:
        flags.append("file looks like a zip but is not a readable zip archive")
    return flags


def inspect_tar(path: Path) -> list[str]:
    flags = []
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for info in archive.getmembers():
                name = info.name
                if looks_like_path_traversal(name) or info.name.startswith("/"):
                    flags.append(f"archive path traversal: {name}")
                if info.issym() or info.islnk():
                    target = info.linkname or ""
                    if looks_like_path_traversal(target):
                        flags.append(f"archive link traversal: {name} -> {target}")
                if not info.isfile():
                    continue
                if dangerous_name(name):
                    flags.append(f"archive contains executable, script, or macro: {name}")
                if info.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    flags.append(f"archive member has execute bits: {name}")
                try:
                    handle = archive.extractfile(info)
                    if handle is None:
                        continue
                    with handle:
                        head = handle.read(16)
                    family = classify_head(head)
                    if family in EXECUTABLE_FAMILIES:
                        flags.append(f"archive contains {family} content: {name}")
                except (tarfile.TarError, OSError):
                    pass
    except tarfile.TarError:
        flags.append("file looks like a tar but is not a readable tar archive")
    return flags


def classify_head(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe")):
        return "macho"
    if data.startswith(b"#!"):
        lower = data.split(b"\n", 1)[0].lower()
        if b"python" in lower:
            return "python"
        if any(token in lower for token in (b"/sh", b"bash", b"zsh", b"dash", b"ksh")):
            return "shell"
        return "script"
    return "other"


def scan_pdf_javascript(path: Path) -> bool:
    # Read-only peek. Stop after 2 MiB so a huge PDF cannot stall intake.
    budget = min(path.stat().st_size, 2 * 1024 * 1024)
    with path.open("rb") as handle:
        data = handle.read(budget)
    return b"/JavaScript" in data or b"/JS" in data


def inspect(path: Path, original_mode: int | None = None) -> dict:
    size = path.stat().st_size
    label, family = sniff(path)
    ext_list = extensions_of(path.name)
    last_ext = ext_list[-1] if ext_list else ""
    flags: list[str] = []

    mode_source = original_mode if original_mode is not None else path.stat().st_mode
    exec_bits = bool(mode_source & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    if exec_bits:
        flags.append("executable bits were set")

    if size > MAX_SIZE:
        flags.append(f"oversized ({size} bytes > 500MB)")

    # Double extension: a safe-looking suffix that is not the final one,
    # or a dangerous final suffix stacked on another suffix (invoice.pdf.exe).
    if len(ext_list) >= 2:
        inner = ext_list[:-1]
        if last_ext in DANGEROUS_EXT:
            flags.append(f"double extension ({path.name})")
        elif any(ext in SAFE_LOOKING_EXT for ext in inner):
            flags.append(f"double extension ({path.name})")

    if last_ext in EXT_FAMILIES and family not in EXT_FAMILIES[last_ext] | {"unknown", "empty"}:
        flags.append(
            f"extension/magic mismatch (name is .{last_ext}, content looks like {family})"
        )

    if family in EXECUTABLE_FAMILIES or last_ext in DANGEROUS_EXT:
        flags.append(f"script or executable content ({family or last_ext})")

    if family == "ole":
        flags.append("OLE document (may contain macros)")
    if last_ext in {"docm", "xlsm", "pptm", "dotm", "xltm", "ppsm"}:
        flags.append(f"Office macro-enabled extension (.{last_ext})")

    if family == "zip":
        flags.extend(inspect_zip(path))
    name_l = path.name.lower()
    if (
        family == "tar"
        or last_ext in {"tar", "tgz"}
        or name_l.endswith((".tar.gz", ".tar.bz2", ".tar.xz"))
    ):
        # inspect_tar uses mode="r:*" and only reads; it never extracts to disk.
        try:
            flags.extend(inspect_tar(path))
        except (tarfile.TarError, OSError, FileNotFoundError):
            pass

    if family == "pdf" and scan_pdf_javascript(path):
        flags.append("PDF contains JavaScript")

    # Deduplicate while preserving order.
    seen = set()
    unique_flags = []
    for flag in flags:
        if flag not in seen:
            seen.add(flag)
            unique_flags.append(flag)

    return {
        "label": label,
        "family": family,
        "extension": last_ext,
        "flags": unique_flags,
        "clean": not unique_flags,
        "size": size,
        "sha256": sha256_file(path),
        "executable_bits_on_intake": exec_bits,
        "sniffer": "file(1)" if shutil.which("file") else "builtin-magic",
    }


def strip_execute_bits(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)


def resolve_quarantined(name: str) -> Path:
    path = Path(name)
    if path.is_absolute():
        try:
            path.relative_to(QUARANTINE.resolve())
        except ValueError:
            # A bare filename might have been given as something else.
            path = QUARANTINE / path.name
    else:
        path = QUARANTINE / path.name
    return path


def cmd_intake(src: str) -> int:
    source = Path(src).expanduser()
    if not source.exists():
        sys.stderr.write(f"No such file: {source}\n")
        return 2
    if not source.is_file():
        sys.stderr.write(f"Not a regular file: {source}\n")
        return 2
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    original_mode = source.stat().st_mode
    dest = unique_dest(QUARANTINE, source.name)
    # Move first, then inspect in place. Never execute.
    shutil.move(str(source), str(dest))
    strip_execute_bits(dest)
    report = inspect(dest, original_mode=original_mode)
    record = {
        "stored_as": dest.name,
        "original_name": source.name,
        "original_path": str(Path(src).expanduser().resolve(strict=False)),
        "intake_time": now_iso(),
        "intake_time_human": now_human(),
        **report,
        "released": False,
    }
    index = load_index()
    index["items"][dest.name] = record
    save_index(index)

    print(f"Quarantined: {dest}")
    print(f"  original:  {record['original_path']}")
    print(f"  size:      {report['size']} bytes")
    print(f"  sha256:    {report['sha256']}")
    print(f"  type:      {report['label']} (family={report['family']}, sniffer={report['sniffer']})")
    if report["flags"]:
        print("  FLAGS:")
        for flag in report["flags"]:
            print(f"    - {flag}")
        print("  Status: HELD (not clean). Release only with --override.")
    else:
        print("  Status: CLEAN. You may release it with: quarantine.py release "
              f"{dest.name} <dest>")
    return 0


def cmd_release(name: str, dest: str, override: bool) -> int:
    stored = resolve_quarantined(name)
    if not stored.is_file():
        sys.stderr.write(f"Not in quarantine: {name}\n")
        return 2
    if stored.resolve() == INDEX_PATH.resolve() or stored.name == "INDEX.json":
        sys.stderr.write("Refusing to release the quarantine index.\n")
        return 2
    index = load_index()
    record = index.get("items", {}).get(stored.name)
    if record is None:
        # File is in the folder but not indexed; inspect now.
        record = inspect(stored)
        record["stored_as"] = stored.name
        record["original_name"] = stored.name
    if record.get("flags") and not override:
        sys.stderr.write(
            f"Refusing to release {stored.name}: it is not clean.\n"
            "Flags:\n"
        )
        for flag in record["flags"]:
            sys.stderr.write(f"  - {flag}\n")
        sys.stderr.write("If you have inspected it and still want it out, rerun with --override.\n")
        return 1
    dest_path = Path(dest).expanduser()
    if dest_path.exists() and dest_path.is_dir():
        dest_path = dest_path / record.get("original_name", stored.name)
    if dest_path.exists():
        sys.stderr.write(f"Destination already exists: {dest_path}\n")
        return 2
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), str(dest_path))
    strip_execute_bits(dest_path)
    if stored.name in index.get("items", {}):
        index["items"][stored.name]["released"] = True
        index["items"][stored.name]["released_to"] = str(dest_path)
        index["items"][stored.name]["released_time"] = now_iso()
        index["items"][stored.name]["released_with_override"] = bool(override)
        # Keep a short history, but drop the live file key by moving to released/.
        released = index.setdefault("released", [])
        released.append(index["items"].pop(stored.name))
        save_index(index)
    print(f"Released {'(OVERRIDE) ' if override else ''}to {dest_path}")
    return 0


def cmd_list() -> int:
    index = load_index()
    items = index.get("items", {})
    if not items:
        print("Quarantine is empty.")
        return 0
    for name, record in items.items():
        status = "CLEAN" if record.get("clean") else "HELD"
        print(f"{name}: {status}  {record.get('label', '?')}  flags={record.get('flags', [])}")
    return 0


def cmd_show(name: str) -> int:
    stored = resolve_quarantined(name)
    index = load_index()
    record = index.get("items", {}).get(stored.name)
    if record is None:
        sys.stderr.write(f"No index entry for {name}\n")
        return 2
    print(json.dumps(record, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Quarantine untrusted files on this computer. Never executes them."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    intake = sub.add_parser("intake", help="Move a file into quarantine and inspect it.")
    intake.add_argument("file")
    release = sub.add_parser("release", help="Move a clean (or overridden) file out.")
    release.add_argument("file")
    release.add_argument("dest")
    release.add_argument(
        "--override",
        action="store_true",
        help="Allow release of a file that still has red flags, after inspection.",
    )
    sub.add_parser("list", help="List quarantined files.")
    show = sub.add_parser("show", help="Print the inspection record for one file.")
    show.add_argument("file")
    args = parser.parse_args(argv)
    if args.cmd == "intake":
        return cmd_intake(args.file)
    if args.cmd == "release":
        return cmd_release(args.file, args.dest, args.override)
    if args.cmd == "list":
        return cmd_list()
    if args.cmd == "show":
        return cmd_show(args.file)
    return 2


if __name__ == "__main__":
    sys.exit(main())
