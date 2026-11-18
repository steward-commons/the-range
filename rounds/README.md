# Rounds (blank)

This folder ships **blank placeholder rounds only**. They show the file format and give the lanes something harmless to score. They contain no real phishing text, no injection payloads, and no attack material.

Write your own rounds, review them by hand, and keep them out of public repos. Run `./range.py seal` to encrypt them into your local armory (Fernet), then delete or lock down the plaintext if you like.

## Naming

`<lane-prefix>-<NN>-<short-name>.<ext>`, for example `ci-01-placeholder.eml`. The round id is the first two parts (`ci-01`).

| Folder | Prefix | Format | Thrown at |
|---|---|---|---|
| `close-in/` | `ci` | `.eml` or `.html` | `check_sender.py` (and `scan_text.py` for HTML) |
| `long-gallery/` | `lg` | `.txt`, `.html`, text-only `.pdf` | `scan_text.py` |
| `grenade-pit/` | `gp` | JSON card: `flood`, `sparse_oversize`, `archive_listing`, `tiny_zip`, `storage_budget` | `grenade.py` evaluators |
| `sci-fi/` | `sf` | JSON card: `supply-chain` or `outage` | `scifi.py` evaluators |
| `no-shoot/` | `ns` | `.eml` or `.txt` | Same as its lane in the course; hitting one is a penalty |

Rules for every round: reserved documentation domains only (`example.com`, `example.org`, `example.net`), made-up people, no real inboxes, no private data, nothing executable.
