"""
Wordlist loading and analysis utilities.

Designed for controlled password-security assessment using user-supplied
laboratory wordlists.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class WordlistStats:
    """Statistics describing a loaded wordlist."""

    path: str
    total_lines: int
    usable_candidates: int
    blank_lines: int
    duplicate_candidates: int
    unique_candidates: int

    def to_dict(self) -> dict:
        """Serialize statistics."""
        return {
            "path": self.path,
            "total_lines": self.total_lines,
            "usable_candidates": self.usable_candidates,
            "blank_lines": self.blank_lines,
            "duplicate_candidates": self.duplicate_candidates,
            "unique_candidates": self.unique_candidates,
        }


class WordlistLoader:
    """Load and inspect user-supplied password wordlists."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

        if not self.path.exists():
            raise FileNotFoundError(
                f"Wordlist not found: {self.path}"
            )

        if not self.path.is_file():
            raise ValueError(
                f"Wordlist path is not a file: {self.path}"
            )

    def iter_candidates(self):
        """Stream usable candidates from the wordlist."""
        with self.path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            for line in file:
                candidate = line.strip()

                if candidate:
                    yield candidate

    def load_unique(self) -> list[str]:
        """Load candidates while preserving their original order."""
        seen: set[str] = set()
        unique: list[str] = []

        for candidate in self.iter_candidates():
            if candidate not in seen:
                seen.add(candidate)
                unique.append(candidate)

        return unique

    def analyze(self) -> WordlistStats:
        """Analyze wordlist quality and duplication."""
        total_lines = 0
        blank_lines = 0
        usable_candidates = 0

        seen: set[str] = set()
        duplicate_candidates = 0

        with self.path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            for line in file:
                total_lines += 1

                candidate = line.strip()

                if not candidate:
                    blank_lines += 1
                    continue

                usable_candidates += 1

                if candidate in seen:
                    duplicate_candidates += 1
                else:
                    seen.add(candidate)

        return WordlistStats(
            path=str(self.path),
            total_lines=total_lines,
            usable_candidates=usable_candidates,
            blank_lines=blank_lines,
            duplicate_candidates=duplicate_candidates,
            unique_candidates=len(seen),
        )