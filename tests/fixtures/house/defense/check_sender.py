#!/usr/bin/env python3
"""House defense layer 2: inspect an email's headers (and body, if present) for spoofing.

A 'clean' verdict means no spoofing signals were found. It is not identity
confirmation. Decide in your own identity policy which channel really counts as
your owner (for example, only the assistant's own app chat). Email should never
be a trusted channel for that.

Trusted addresses may be passed with --trusted at runtime. They are never
written to disk by this tool.
"""

from __future__ import annotations

import argparse
import os
import email
import email.policy
import email.utils
import re
import sys
from email.message import EmailMessage, Message
from pathlib import Path

DEFENSE = Path(__file__).resolve().parent
if str(DEFENSE) not in sys.path:
    sys.path.insert(0, str(DEFENSE))

import scan_text  # noqa: E402

# Brand domains we watch for lookalikes. Not a contact list.
PROTECTED_DOMAINS = (
    "gmail.com",
    "yahoo.com",
    "google.com",
    "outlook.com",
    "icloud.com",
)

# Display names that should not appear with an untrusted From address.
# Empty by default. Pass --protected-names or set CHECK_SENDER_PROTECTED_NAMES
# (comma-separated) with your own household's display names. No addresses.
DEFAULT_PROTECTED_NAMES: tuple[str, ...] = tuple(
    n.strip() for n in os.environ.get("CHECK_SENDER_PROTECTED_NAMES", "").split(",") if n.strip()
)

# Homoglyph / leetspeak map into ASCII lookalikes.
HOMO = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "!": "i",
    "|": "l",
    "@": "a",
    "$": "s",
    "а": "a",  # Cyrillic
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
})

BODY_FLAG_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in [
        ("urgent gift-card or money request", r"\bgift\s*cards?\b|\bwires?\s+(me\s+)?(the\s+)?money\b|\bwestern\s+union\b"),
        ("secrecy ('don't tell the owner')", r"\bdon['’]?t\s+tell\s+(the\s+owner|anyone|him|her|my\s+(son|daughter|dad|mom|father|mother))\b|\bkeep\s+this\s+(between\s+us|secret)\b"),
        ("new account or number claim", r"\bi(['’]m|\s+am)\s+\w+\b.{0,40}\bnew\s+(account|number|phone)\b|\bthis\s+is\s+my\s+new\s+(account|number|phone)\b"),
        ("request for codes, vault, or passwords", r"\b(send|give|tell)\b.{0,24}\b(codes?|pin|password|vault|credentials)\b"),
        ("urgency plus payment", r"\b(urgent|immediately|right\s+now|asap)\b.+\b(gift\s*card|wire|venmo|zelle|bitcoin|payment|money)\b"),
        ("request to change rules or access", r"\b(change|update|replace)\b.{0,24}\b(your\s+)?(rules|routines|contacts|sharing|password|access)\b"),
    ]
]

AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)",
    re.IGNORECASE,
)
FAILISH = {"fail", "softfail", "permerror"}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def normalize_domain(domain: str) -> str:
    # Shared typography skeleton first (NFKC, invisibles, script confusables),
    # then the domain-only leetspeak map. The original header is not rewritten.
    text = scan_text.normalize_for_scan(domain).lower().strip().rstrip(".")
    text = text.translate(HOMO)
    text = text.replace("rn", "m").replace("vv", "w")
    return text


def parse_address(raw: str | None) -> tuple[str, str]:
    """Return (display_name, lowercase_address) from a header value."""
    if not raw:
        return "", ""
    # Return-Path is often just <addr>.
    name, addr = email.utils.parseaddr(raw)
    return name.strip(), (addr or "").strip().lower()


def all_addresses(raw: str | None) -> list[tuple[str, str]]:
    if not raw:
        return []
    return [
        (name.strip(), (addr or "").strip().lower())
        for name, addr in email.utils.getaddresses([raw])
        if name or addr
    ]


def domain_of(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower().strip().rstrip(".")


def is_real_or_subdomain(domain: str, protected: str) -> bool:
    return domain == protected or domain.endswith("." + protected)


def lookalike_reasons(domain: str) -> list[str]:
    if not domain:
        return []
    reasons = []
    nd = normalize_domain(domain)
    for prot in PROTECTED_DOMAINS:
        np = normalize_domain(prot)
        if is_real_or_subdomain(domain, prot):
            continue
        if nd == np or is_real_or_subdomain(nd, np):
            reasons.append(
                f"lookalike domain: {domain} ≈ {prot} (homoglyph / normalized match)"
            )
            continue
        if nd.startswith(np + ".") or domain.startswith(prot + "."):
            reasons.append(
                f"lookalike domain: {domain} embeds {prot} as a prefix"
            )
            continue
        # Short protected domains (x.ai) only match via homoglyph, not edit distance.
        if len(np) <= 5:
            continue
        dist = levenshtein(nd, np)
        max_dist = 1 if len(np) <= 8 else 2
        if 0 < dist <= max_dist:
            reasons.append(
                f"lookalike domain: {domain} ≈ {prot} (edit distance {dist})"
            )
    # Dedup
    seen: set[str] = set()
    out = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            out.append(reason)
    return out


def name_is_protected(display: str, protected_names: tuple[str, ...] | list[str]) -> str | None:
    if not display:
        return None
    compact = " ".join(display.split())
    haystacks = [compact.casefold()]
    skeleton = scan_text.normalize_for_scan(compact)
    folded = skeleton.casefold()
    if folded not in haystacks:
        haystacks.append(folded)
    for name in protected_names:
        needle = " ".join(name.split()).casefold()
        if not needle:
            continue
        # Whole-phrase match, not a prefix of a longer word (Ann vs Anna).
        pattern = re.compile(r"\b" + re.escape(needle) + r"\b", re.IGNORECASE)
        for haystack in haystacks:
            if pattern.search(haystack):
                return name
    return None


def parse_auth_results(msg: Message) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    values = msg.get_all("Authentication-Results") or []
    for value in values:
        for match in AUTH_RESULT_RE.finditer(value):
            found.append((match.group(1).lower(), match.group(2).lower()))
    return found


def extract_body(msg: Message) -> str:
    texts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue
            if part.get_content_type() == "text/plain":
                texts.append(_decode_part(part))
        if not texts:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    texts.append(_strip_html(_decode_part(part)))
    else:
        ctype = msg.get_content_type()
        payload = _decode_part(msg)
        if ctype == "text/html":
            texts.append(_strip_html(payload))
        else:
            texts.append(payload)
    return "\n".join(t for t in texts if t).strip()


def _decode_part(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except (AttributeError, LookupError, ValueError):
        payload = None
    if payload is None:
        data = part.get_payload()
        return data if isinstance(data, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _strip_html(text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def load_message(path_or_dash: str) -> Message:
    policy = email.policy.default
    if path_or_dash == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(path_or_dash).read_bytes()
    # A headers-only file may lack the blank line that starts a body.
    if b"\n\n" not in data and b"\r\n\r\n" not in data:
        if not data.endswith(b"\n"):
            data += b"\n"
        data += b"\n"
    return email.message_from_bytes(data, policy=policy)


def parse_trusted(values: list[str] | None) -> set[str]:
    trusted: set[str] = set()
    for value in values or []:
        for part in value.split(","):
            addr = part.strip().lower()
            if addr:
                trusted.add(addr)
    return trusted


def inspect(
    msg: Message,
    trusted: set[str],
    protected_names: tuple[str, ...] | list[str],
) -> dict:
    reasons: list[str] = []
    score = 0

    from_name, from_addr = parse_address(msg.get("From"))
    reply_to = all_addresses(msg.get("Reply-To"))
    return_path_name, return_path = parse_address(msg.get("Return-Path"))
    from_domain = domain_of(from_addr)

    if from_addr and reply_to:
        reply_addrs = {addr for _name, addr in reply_to if addr}
        if reply_addrs and from_addr not in reply_addrs:
            reasons.append(
                f"From vs Reply-To mismatch ({from_addr} vs {', '.join(sorted(reply_addrs))})"
            )
            score += 1

    if from_addr and return_path and return_path != from_addr:
        reasons.append(f"Return-Path mismatch ({from_addr} vs {return_path})")
        score += 1

    matched_name = name_is_protected(from_name, protected_names)
    if matched_name:
        if from_addr and from_addr in trusted:
            pass  # matching display name with a runtime-trusted address is fine
        else:
            if trusted:
                reasons.append(
                    f"display-name impersonation: '{from_name}' claims '{matched_name}' "
                    "but the From address is not on the runtime trusted list"
                )
            else:
                reasons.append(
                    f"display-name impersonation: '{from_name}' claims '{matched_name}' "
                    "with no runtime trusted list to verify against"
                )
            score += 3

    for reason in lookalike_reasons(from_domain):
        reasons.append(reason)
        score += 3

    for mechanism, result in parse_auth_results(msg):
        if result in FAILISH:
            bump = 2 if mechanism == "dmarc" else 1
            reasons.append(f"{mechanism.upper()} {result} in Authentication-Results")
            score += bump

    body = extract_body(msg)
    body_flags: list[str] = []
    scan_hits: list[tuple[int, str, str]] = []
    if body:
        body_for_scan = scan_text.normalize_for_scan(body)
        for label, pattern in BODY_FLAG_PATTERNS:
            if pattern.search(body_for_scan):
                body_flags.append(label)
        if body_flags:
            reasons.append("body red flags: " + "; ".join(body_flags))
            score += 2
        scan_hits = scan_text.scan_text(body)
        if scan_hits:
            labels = ", ".join(sorted({label for _line, label, _ex in scan_hits}))
            reasons.append(f"body also flagged by scan_text.py: {labels}")
            score += 1

    if score >= 3 or any(
        r.startswith("display-name impersonation") or r.startswith("lookalike domain")
        for r in reasons
    ):
        verdict = "likely spoof"
    elif score >= 1:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "from_name": from_name,
        "from_addr": from_addr,
        "body_flags": body_flags,
        "scan_hits": scan_hits,
        "trusted_from": bool(from_addr and from_addr in trusted),
    }


def format_report(result: dict) -> str:
    lines = [f"Verdict: {result['verdict']}"]
    if result["from_addr"] or result["from_name"]:
        who = result["from_addr"] or "(no From address)"
        if result["from_name"]:
            who = f"{result['from_name']} <{result['from_addr']}>"
        extra = " (on runtime trusted list)" if result["trusted_from"] else ""
        lines.append(f"From: {who}{extra}")
    if result["reasons"]:
        lines.append("Reasons:")
        for reason in result["reasons"]:
            lines.append(f"  - {reason}")
    else:
        lines.append(
            "Reasons: none. This is not identity confirmation — email is never "
            "a trusted channel for the owner."
        )
    if result["scan_hits"]:
        lines.append("scan_text.py hits:")
        for lineno, label, excerpt in result["scan_hits"]:
            lines.append(f"  L{lineno}  [{label}]  {excerpt}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Flag spoofing signals in an email's headers or a .eml file. "
            "A clean verdict is not proof of identity."
        )
    )
    parser.add_argument(
        "path",
        help="Path to a .eml file or a raw-headers file, or '-' for stdin.",
    )
    parser.add_argument(
        "--trusted",
        action="append",
        default=[],
        help=(
            "Trusted address, or a comma-separated list. Repeatable. "
            "Used only in memory at runtime; never written to disk."
        ),
    )
    parser.add_argument(
        "--protected-names",
        default="",
        help=(
            "Comma-separated display names to protect, replacing "
            "CHECK_SENDER_PROTECTED_NAMES. Optional."
        ),
    )
    args = parser.parse_args(argv)
    if args.path != "-" and not Path(args.path).is_file():
        sys.stderr.write(f"No such file: {args.path}\n")
        return 3
    try:
        msg = load_message(args.path)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"Could not read email: {exc}\n")
        return 3

    trusted = parse_trusted(args.trusted)
    if args.protected_names.strip():
        names = [n.strip() for n in args.protected_names.split(",") if n.strip()]
    else:
        names = list(DEFAULT_PROTECTED_NAMES)

    result = inspect(msg, trusted, names)
    print(format_report(result))
    if result["verdict"] == "clean":
        return 0
    if result["verdict"] == "suspicious":
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
