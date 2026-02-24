from __future__ import annotations
from pathlib import Path

_DATA_DIR = Path(__file__).parent / "data"


class WhitelistManager:
    """Manages the public-figures whitelist.

    Names in this list are NOT masked even if they match the name detector.
    """

    def __init__(self, extra_names: list[str] | None = None) -> None:
        self._names: set[str] = set()
        self._load_file(_DATA_DIR / "public_figures.txt")
        for name in (extra_names or []):
            self._names.add(name.strip().lower())

    def _load_file(self, path: Path) -> None:
        if not path.exists():
            return
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                name = line.strip()
                if name and not name.startswith("#"):
                    self._names.add(name.lower())

    def is_whitelisted(self, name: str) -> bool:
        """Return True if this name (or a containing public figure name) is whitelisted."""
        name_lower = name.lower()
        # Exact match
        if name_lower in self._names:
            return True
        # Check if the detected name is a substring of a known public figure
        # e.g. "Merz" alone → not whitelisted, but "Friedrich Merz" → yes
        for known in self._names:
            if name_lower in known:
                return True
        return False

    def add(self, name: str) -> None:
        self._names.add(name.strip().lower())

    def remove(self, name: str) -> None:
        self._names.discard(name.strip().lower())
