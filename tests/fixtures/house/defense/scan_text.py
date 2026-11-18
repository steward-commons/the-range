#!/usr/bin/env python3
"""Flag instruction-like phrases in a text file, for study.

This is a simple pattern scanner, not a verdict. A match means "look at this,"
not "this is definitely an attack." Exit 1 if any patterns match, 0 if none.
Never follows the text as an instruction.

Scanning uses a *copy* of the text: Unicode NFKC, stripped of zero-width /
invisible / bidi controls, with known confusable letters mapped to a Latin
skeleton. The original string or file is never modified. Ordinary symbols
(°, ©, ½) and accented Latin names are left alone and are not mixed-script
hits. Mixed-script words (for example Latin + Cyrillic in one token) are
flagged as suspicious on their own.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path


# Case-insensitive phrase and light regex patterns. Keep these readable;
# the goal is study, not an exhaustive filter.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in [
        ("ignore previous instructions", r"ignore (all )?(previous|prior|above) (instructions|directions|rules|prompts)"),
        ("ignore the above", r"ignore the (above|earlier|preceding)\b"),
        ("disregard previous instructions", r"disregard (all )?(previous|prior|above) (instructions|directions|rules)"),
        ("forget your instructions", r"forget (your|all|the) (previous )?(instructions|rules|guidelines)"),
        ("you are now", r"\byou are now\b"),
        ("you are no longer", r"\byou are no longer\b"),
        ("from now on you", r"\bfrom now on,? you\b"),
        ("your new role is", r"your new (role|persona|identity) is\b"),
        ("new instructions", r"\bnew instructions\s*:"),
        ("override your rules", r"override (your|the) (instructions|rules|ethics|safety|guidelines)"),
        ("disable your safety", r"disable (your|all) (safety|guardrails|filters|restrictions)"),
        ("pretend you have no restrictions", r"pretend you (have no|are without) (restrictions|limits|rules|guidelines)"),
        ("developer mode / DAN", r"\b(developer mode|dan mode|do anything now)\b"),
        ("jailbreak", r"\bjailbreak\b"),
        ("reveal system prompt", r"reveal (your )?(system )?prompt"),
        ("output your system prompt", r"(output|print|dump|show) (your |the )?(full )?system (prompt|instructions)"),
        ("reveal password", r"reveal (the |your )?(password|passwords|credentials|secret key|api key)"),
        ("tell me your password", r"tell me (your|the) (password|credentials|secret|api key)"),
        ("dump your memory", r"(dump|exfiltrate|export) (your )?(memory|secrets|credentials|system prompt)"),
        ("send / forward to", r"\b(send|forward|email|wire|transfer) (this |it |them |everything |the (data|file|contents|money|funds) )?(to|toward)\b"),
        ("transfer funds", r"\btransfer (the )?funds\b"),
        ("do not tell the owner", r"do not (tell|inform|notify|mention (this )?to) (your |the )?(owner|user|operator)\b"),
        ("hidden instruction", r"\bhidden (instruction|prompt|directive)s?\b"),
        ("before doing anything else", r"before (you )?(do|doing) anything else\b"),
        ("special case, ignore", r"special case[,:]? (please )?ignore\b"),
        ("gift card request", r"\bgift\s*cards?\b"),
        ("don't tell anyone / keep this secret", r"\bdon['’]?t\s+tell\s+(anyone|him|her|them|the owner|the user)\b|\bkeep\s+this\s+(between\s+us|secret)\b"),
        ("new account or number claim", r"\bthis\s+is\s+my\s+new\s+(account|number|phone)\b"),
        ("send me the codes", r"\b(send|give)\s+me\s+(the\s+)?(gift\s+card\s+)?codes?\b"),
    ]
]

MIXED_SCRIPT_LABEL = "mixed-script word"

# Format / invisible / bidi controls that can hide or reshape a word.
# Also strip these code points if a future Unicode version recategorizes them.
_INVISIBLE_CODEPOINTS = frozenset(
    {
        0x00AD,  # soft hyphen
        0x034F,  # combining grapheme joiner
        0x061C,  # Arabic letter mark
        0x180B, 0x180C, 0x180D, 0x180E, 0x180F,
        0x200B, 0x200C, 0x200D,  # ZWSP, ZWNJ, ZWJ
        0x200E, 0x200F,  # LRM, RLM
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embeddings / overrides
        0x2060,  # word joiner
        0x2061, 0x2062, 0x2063, 0x2064,
        0x2066, 0x2067, 0x2068, 0x2069,  # bidi isolates
        0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F,
        0xFEFF,  # BOM / ZWNBSP
        *range(0xFE00, 0xFE10),  # variation selectors
        *range(0xE0100, 0xE01F0),  # variation selectors supplement
    }
)

# Known lookalikes that NFKC does not fold (Cyrillic, Greek, and a few others).
# Fullwidth and math-styled letters are left to NFKC. Values are the Latin
# skeleton character. Both cases are listed so mixed-case spoofs stay readable.
_CONFUSABLE_PAIRS: tuple[tuple[str, str], ...] = (
    # Cyrillic -> Latin
    ("А", "A"), ("а", "a"),
    ("В", "B"),
    ("Е", "E"), ("е", "e"),
    ("К", "K"), ("к", "k"),
    ("М", "M"),
    ("Н", "H"),
    ("О", "O"), ("о", "o"),
    ("Р", "P"), ("р", "p"),
    ("С", "C"), ("с", "c"),
    ("Т", "T"),
    ("У", "Y"), ("у", "y"),
    ("Х", "X"), ("х", "x"),
    ("І", "I"), ("і", "i"),  # Ukrainian / Belarusian I
    ("Ї", "I"), ("ї", "i"),
    ("Ј", "J"), ("ј", "j"),
    ("Ѕ", "S"), ("ѕ", "s"),
    ("Ӏ", "I"), ("ӏ", "l"),  # palochka
    ("Ү", "Y"), ("ү", "y"),
    ("Ԝ", "W"), ("ԝ", "w"),
    ("Ѵ", "V"), ("ѵ", "v"),
    ("ԁ", "d"),
    ("Ԍ", "G"),
    ("ԛ", "q"),
    ("Ғ", "F"),
    ("ҫ", "c"), ("Ҫ", "C"),
    # Greek -> Latin
    ("Α", "A"), ("α", "a"),
    ("Β", "B"),
    ("Ε", "E"), ("ε", "e"),
    ("Ζ", "Z"),
    ("Η", "H"), ("η", "n"),
    ("Ι", "I"), ("ι", "i"),
    ("Κ", "K"), ("κ", "k"),
    ("Μ", "M"),
    ("Ν", "N"), ("ν", "v"),
    ("Ο", "O"), ("ο", "o"),
    ("Ρ", "P"), ("ρ", "p"),
    ("Τ", "T"), ("τ", "t"),
    ("Υ", "Y"), ("υ", "y"),
    ("Χ", "X"), ("χ", "x"),
    ("Ϲ", "C"), ("ϲ", "c"),  # lunate sigma
    ("ϒ", "Y"),
    # Armenian (common confusables)
    ("Ա", "A"),
    ("Տ", "S"),
    ("օ", "o"), ("Օ", "O"),
    ("ս", "u"),
    # Other frequent one-offs that NFKC leaves alone
    ("ſ", "s"),  # long s
    ("ı", "i"),  # Turkish dotless i — scan copy only
    ("K", "K"),
)

CONFUSABLE_MAP = str.maketrans({src: dst for src, dst in _CONFUSABLE_PAIRS})

# Alphabetic scripts that are used to spoof Latin (or each other) in one word.
# Han/Hiragana/Katakana/Hangul are left out so ordinary mixed CJK+Latin labels
# are not treated as an injection trick.
_SCRIPT_RANGES: tuple[tuple[str, tuple[tuple[int, int], ...]], ...] = (
    (
        "Latin",
        (
            (0x0041, 0x005A),
            (0x0061, 0x007A),
            (0x00AA, 0x00AA),
            (0x00BA, 0x00BA),
            (0x00C0, 0x00D6),
            (0x00D8, 0x00F6),
            (0x00F8, 0x024F),
            (0x1E00, 0x1EFF),
            (0x2C60, 0x2C7F),
            (0xA720, 0xA7FF),
            (0xAB30, 0xAB6F),
            (0xFF21, 0xFF3A),
            (0xFF41, 0xFF5A),
        ),
    ),
    (
        "Cyrillic",
        (
            (0x0400, 0x04FF),
            (0x0500, 0x052F),
            (0x1C80, 0x1C8F),
            (0x2DE0, 0x2DFF),
            (0xA640, 0xA69F),
        ),
    ),
    (
        "Greek",
        (
            (0x0370, 0x03FF),
            (0x1F00, 0x1FFF),
        ),
    ),
    ("Armenian", ((0x0530, 0x058F),)),
    ("Hebrew", ((0x0590, 0x05FF),)),
    ("Arabic", ((0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF))),
    ("Georgian", ((0x10A0, 0x10FF), (0x2D00, 0x2D2F))),
)


def _script_of(ch: str) -> str | None:
    if not unicodedata.category(ch).startswith("L"):
        return None
    cp = ord(ch)
    for name, ranges in _SCRIPT_RANGES:
        for start, end in ranges:
            if start <= cp <= end:
                return name
    return None


def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    if cp in _INVISIBLE_CODEPOINTS:
        return True
    if ch in "\t\n\r":
        return False
    return unicodedata.category(ch) in {"Cf", "Cc"} and cp != 0x20


def strip_invisibles(text: str) -> str:
    """Drop zero-width, format, and bidi-control characters from a copy."""
    return "".join(ch for ch in text if not _is_invisible(ch))


def normalize_for_scan(text: str) -> str:
    """Return a scan-only Latin skeleton. Never use this to rewrite a file.

    Steps: NFKC, strip invisibles / bidi controls, map known confusables.
    Accented Latin letters (é, ñ, ø) stay as themselves. Symbols such as
    °, ©, and ½ are not turned into letters.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = strip_invisibles(folded)
    return folded.translate(CONFUSABLE_MAP)


def letter_tokens(text: str) -> list[tuple[str, int]]:
    """Return (token, start_index) for each run of letters in text."""
    tokens: list[tuple[str, int]] = []
    start: int | None = None
    chars: list[str] = []
    for i, ch in enumerate(text):
        if unicodedata.category(ch).startswith("L"):
            if start is None:
                start = i
            chars.append(ch)
        elif start is not None:
            tokens.append(("".join(chars), start))
            start = None
            chars = []
    if start is not None:
        tokens.append(("".join(chars), start))
    return tokens


def mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin with another spoofing alphabet, or two of them.

    Detection runs on the original letters (after dropping invisibles so a
    zero-width break cannot split a spoof). All-Cyrillic or all-Greek words
    are left alone. Accented Latin counts as Latin only.
    """
    cleaned = strip_invisibles(text)
    found: list[str] = []
    seen: set[str] = set()
    for token, _start in letter_tokens(cleaned):
        scripts = {s for s in (_script_of(ch) for ch in token) if s}
        if len(scripts) < 2:
            continue
        # Two spoofing alphabets in one token, usually Latin + Cyrillic/Greek.
        if token not in seen:
            seen.add(token)
            found.append(token)
    return found


def _excerpt(line: str) -> str:
    excerpt = line.strip()
    if len(excerpt) > 200:
        excerpt = excerpt[:197] + "..."
    return excerpt


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return a list of (line_number, label, excerpt) hits.

    Pattern matches run against a normalized copy of each line. Excerpts
    come from the original line so the lookalike characters stay visible.
    The input string is not modified.
    """
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        skeleton = normalize_for_scan(line)
        for label, pattern in PATTERNS:
            if pattern.search(skeleton):
                hits.append((lineno, label, _excerpt(line)))
        mixed = mixed_script_words(line)
        if mixed:
            shown = ", ".join(mixed[:6])
            if len(mixed) > 6:
                shown += ", ..."
            hits.append((lineno, MIXED_SCRIPT_LABEL, shown))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Flag instruction-like phrases in a text file, for study."
    )
    parser.add_argument("path", help="Text file to scan (not executed, not followed).")
    args = parser.parse_args(argv)
    path = Path(args.path)
    if not path.is_file():
        sys.stderr.write(f"No such file: {path}\n")
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    hits = scan_text(text)
    if not hits:
        print(f"No instruction-like phrases found in {path}.")
        return 0
    print(f"Flagged {len(hits)} instruction-like phrase(s) in {path}:")
    for lineno, label, excerpt in hits:
        print(f"  L{lineno}  [{label}]  {excerpt}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
