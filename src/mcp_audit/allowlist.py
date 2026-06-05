"""Per-finding allowlist for suppressing false positives.

A security scanner that cries wolf loses its audience, so every finding carries a stable
fingerprint and a user can permanently suppress one by adding that fingerprint to an
allowlist. Two locations are read (project-local wins by being listed first, but membership
is a union): `<root>/.mcp-audit/allowlist` and `~/.mcp-audit/allowlist`. One fingerprint per
line; `#` starts a comment.
"""
from __future__ import annotations

from pathlib import Path

_REL = Path(".mcp-audit") / "allowlist"


def _candidate_paths(root: Path | None) -> list[Path]:
    raw = []
    if root is not None:
        raw.append(root / _REL)
    raw.append(Path.cwd() / _REL)
    raw.append(Path.home() / _REL)
    seen: set[str] = set()
    out: list[Path] = []
    for p in raw:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def load_allowlist(root: Path | None = None) -> set[str]:
    """Union of fingerprints across the project and home allowlists."""
    hashes: set[str] = set()
    for path in _candidate_paths(root):
        try:
            text = path.read_text("utf-8", "ignore")
        except OSError:
            continue
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry:
                hashes.add(entry)
    return hashes


def add_to_allowlist(fingerprint: str, root: Path | None = None) -> Path:
    """Append a fingerprint to the project allowlist (created if needed). Idempotent."""
    target = (root or Path.cwd()) / _REL
    target.parent.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if target.exists():
        for line in target.read_text("utf-8", "ignore").splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry:
                existing.add(entry)
    if fingerprint not in existing:
        with target.open("a", encoding="utf-8") as fh:
            fh.write(f"{fingerprint}\n")
    return target
