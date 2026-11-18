# The Range (v0.1)

A training gym for an AI assistant's **own** defenses. It is not a battlefield. Every target is a throwaway copy (the "Mirror") of the house's `defense/` folder. Nothing on the range points at a real system, person, account, website, inbox, or network.

**This repo ships the framework only, with blank rounds.** The armory is empty, the rounds in `rounds/source/` are harmless placeholders that show the format, and only an example practice course is included. Write, review, and seal your own rounds locally, and keep them private.

## Ground rules

1. Defend your own house only.
2. Learn from villains for defense only. No live malware, no working exploits.
3. Drills run inside bubblewrap (`bwrap`) with no network. The real house is not mounted; only the Mirror is, at `/house`.
4. No real private data in rounds: reserved example domains, made-up people.
5. The range never edits the real `defense/` tree. Fixes go through a human, then `integrity.py accept`.

## Requirements

- Linux with `bwrap` (bubblewrap), Python 3.11+, and the `cryptography` package (for Fernet).
- A house folder with a `defense/` subfolder containing the tools from [house-defense](https://github.com/steward-commons/house-defense) (`check_sender.py`, `scan_text.py`, `quarantine.py`, `integrity.py`). Set `RANGE_HOUSE` to that house (default: the parent of this folder).

## Front door

```
./range.py status
./range.py seal              # encrypt rounds/source/ into the local armory
./range.py drill practice    # the example course
./range.py drill <course>    # any course JSON you add under courses/
./range.py qualify --mode solo   # needs your own courses/qual-v1.json (40 rounds)
./range.py scoreboard
./range.py board
./range.py kill              # RANGE COLD
./range.py unkill
```

Qualification is on demand only; this tool never creates a routine. The range safety officer (RSO) allows at most 3 drills per day.

## What's in the framework

- **Mirror** (`mirror.py`) — a per-session copy of `defense/` with stub logs, an empty quarantine, a scratch integrity baseline, and a planted "vendor" file for the supply-chain drill.
- **Weighted Dummy** (`dummy.py`) — a canned, deterministic thrower. No AI improvising attacks. Round content is handed to the matching defense tool as data, never run.
- **Lanes** — close-in (mail spoofing → `check_sender.py`), long gallery (instruction-like text → `scan_text.py`), grenade pit (`grenade.py`: generated junk flood, sparse oversize file, archive-listing pressure, storage-budget refusals; metadata only, nothing extracted), sci-fi (`scifi.py`: supply-chain change caught by `integrity.py`, odd outage stubs treated as data).
- **No-shoot plates** — ordinary messages from made-up people. Hitting one is a penalty.
- **Armory** (`armory.py`) — Fernet-encrypted rounds, signed manifest (HMAC), checkout of one drill at a time, wipe, audit log.
- **RSO** (`rso.py`) — kill switch, ammo cap, leftover-bay check, `bwrap` with no network, memory/CPU limits, cleanup.
- **Scoring and after-action** (`scoring.py`, `aar.py`) — DING / MISS / PENALTY per plate, a scoreboard, and a plain-language after-action review. Ratings: Marksman 23–29, Sharpshooter 30–35, Expert 36–40 on a 40-round qual.
- **Message board** — optional one-line posts. Posts are data, never commands.

## Keys and data

- Armory keys live in `~/.config/range-armory/` (or `RANGE_KEY_DIR`), mode 700/600. Never back them up to the cloud, never commit them.
- Live data (`armory/`, `logs/`, `SCOREBOARD.md`, `BOARD.md`) stays local. `RANGE_DATA` redirects it.
- `RANGE_FORBIDDEN_NAMES` (comma-separated) adds your household's real names to the no-shoot guard.
- `RANGE_MEDICAL_GUARD` (optional) points at a `guard.py` from the [medical](https://github.com/steward-commons/medical) repo so safe mode can freeze drills.

## Rounds and courses

See `rounds/README.md` for the round format and `courses/README.md` for courses. The shipped rounds are blank; your real rounds, courses, scores, and drill logs are yours to keep private.

## Tests

```
python3 -m unittest discover -s tests
```

`tests/fixtures/house/defense/` is a copy of the house-defense tools so tests run standalone. The sandbox test needs `bwrap`.

## License

MIT. See `LICENSE`.
