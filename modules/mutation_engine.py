"""
Controlled password mutation and hybrid candidate generation.

This module generates synthetic password candidates from supplied
base words for offline credential-security testing.

It does not perform authentication or interact with live systems.
"""

from dataclasses import dataclass
from typing import Iterable


LEET_REPLACEMENTS = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "$",
    "t": "7",
}


@dataclass
class MutationConfig:
    """Configuration controlling candidate mutation behavior."""

    case_variations: bool = True
    number_suffixes: bool = True
    symbol_suffixes: bool = True
    leetspeak: bool = True
    reversed_variant: bool = True
    duplicate_variant: bool = False

    numbers: tuple[str, ...] = (
        "0",
        "1",
        "12",
        "123",
        "2024",
        "2025",
        "2026",
    )

    symbols: tuple[str, ...] = (
        "!",
        "@",
        "#",
        "$",
    )


class MutationEngine:
    """Generate controlled password candidates from supplied base words."""

    def __init__(self, config: MutationConfig | None = None) -> None:
        self.config = config or MutationConfig()

    def _case_variants(self, word: str) -> set[str]:
        """Return common case variations."""

        return {
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
        }

    def _leet_variant(self, word: str) -> str:
        """Convert characters to a deterministic leetspeak variant."""

        return "".join(
            LEET_REPLACEMENTS.get(character.lower(), character)
            for character in word
        )

    def _generate_for_word(self, word: str) -> set[str]:
        """Generate mutations for one base word."""

        candidates: set[str] = set()

        # Always preserve the original supplied candidate.
        candidates.add(word)

        # Case variations.
        if self.config.case_variations:
            candidates.update(self._case_variants(word))

        # Leetspeak variants.
        if self.config.leetspeak:
            leet = self._leet_variant(word)
            candidates.add(leet)

            if self.config.case_variations:
                candidates.add(leet.lower())
                candidates.add(leet.upper())
                candidates.add(leet.capitalize())

        # Reversed candidate.
        if self.config.reversed_variant:
            candidates.add(word[::-1])

        # Duplicate candidate.
        if self.config.duplicate_variant:
            candidates.add(word + word)

        # Number suffixes.
        if self.config.number_suffixes:
            for number in self.config.numbers:
                candidates.add(word + number)

        # Symbol suffixes.
        if self.config.symbol_suffixes:
            for symbol in self.config.symbols:
                candidates.add(word + symbol)

        # Number + symbol combinations.
        if self.config.number_suffixes and self.config.symbol_suffixes:
            for number in self.config.numbers:
                for symbol in self.config.symbols:
                    candidates.add(word + number + symbol)

        # Apply the same suffix strategy to common case variants.
        if self.config.case_variations:
            case_variants = self._case_variants(word)

            for variant in case_variants:
                for number in self.config.numbers:
                    candidates.add(variant + number)

                for symbol in self.config.symbols:
                    candidates.add(variant + symbol)

        return candidates

    def generate(
        self,
        words: Iterable[str],
        max_candidates: int | None = None,
    ) -> list[str]:
        """
        Generate a deterministic, unique candidate list.

        The original supplied words are always retained.

        Args:
            words: Base words supplied by the controlled lab.
            max_candidates: Optional upper bound on generated candidates.

        Returns:
            Unique candidates in deterministic sorted order.
        """

        if max_candidates is not None and max_candidates < 1:
            return []

        generated: set[str] = set()

        for raw_word in words:
            if not isinstance(raw_word, str):
                continue

            word = raw_word.strip()

            if not word:
                continue

            generated.update(self._generate_for_word(word))

            if max_candidates is not None and len(generated) >= max_candidates:
                break

        candidates = sorted(generated)

        if max_candidates is not None:
            candidates = candidates[:max_candidates]

        return candidates

    def generate_to_file(
        self,
        words: Iterable[str],
        output_path: str,
        max_candidates: int | None = None,
    ) -> int:
        """
        Generate candidates and write them to a UTF-8 wordlist.

        Returns:
            Number of candidates written.
        """

        candidates = self.generate(
            words,
            max_candidates=max_candidates,
        )

        with open(output_path, "w", encoding="utf-8") as file:
            for candidate in candidates:
                file.write(candidate + "\n")

        return len(candidates)