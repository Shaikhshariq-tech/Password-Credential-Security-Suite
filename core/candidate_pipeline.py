"""
Candidate processing pipeline for controlled password-security testing.

The pipeline combines supplied candidates with optional password mutations
while enforcing strict limits and removing duplicates.
"""

from collections.abc import Iterable, Iterator

from config.settings import MAX_SIMULATION_ATTEMPTS
from modules.mutation_engine import MutationEngine, MutationConfig


class CandidatePipeline:
    """
    Build a controlled stream of password candidates.

    Features:
    - candidate normalization
    - duplicate elimination
    - optional mutation generation
    - hard candidate limits
    - streaming instead of storing huge lists
    """

    def __init__(
        self,
        max_candidates: int = MAX_SIMULATION_ATTEMPTS,
        mutation_config: MutationConfig | None = None,
    ):
        if max_candidates <= 0:
            raise ValueError(
                "max_candidates must be greater than zero."
            )

        if max_candidates > MAX_SIMULATION_ATTEMPTS:
            raise ValueError(
                f"max_candidates cannot exceed "
                f"{MAX_SIMULATION_ATTEMPTS:,}."
            )

        self.max_candidates = max_candidates
        self.mutation_engine = MutationEngine(
            config=mutation_config
            or MutationConfig()
        )

    @staticmethod
    def _clean_candidate(candidate: str) -> str | None:
        """Normalize an individual candidate."""
        if not isinstance(candidate, str):
            return None

        candidate = candidate.strip()

        if not candidate:
            return None

        return candidate

    def from_candidates(
        self,
        candidates: Iterable[str],
        mutate: bool = False,
    ) -> Iterator[str]:
        """
        Generate unique candidates from an iterable.

        When mutate=True, each supplied base candidate is passed through
        the mutation engine.
        """
        seen: set[str] = set()
        produced = 0

        for candidate in candidates:
            cleaned = self._clean_candidate(candidate)

            if cleaned is None:
                continue

            candidate_group = (
                self.mutation_engine.generate(
                    cleaned,
                    max_candidates=self.max_candidates,
                )
                if mutate
                else [cleaned]
            )

            for generated in candidate_group:
                generated = self._clean_candidate(generated)

                if generated is None:
                    continue

                if generated in seen:
                    continue

                seen.add(generated)
                yield generated

                produced += 1

                if produced >= self.max_candidates:
                    return

    def from_wordlist(
        self,
        wordlist_path: str,
        mutate: bool = False,
    ) -> Iterator[str]:
        """
        Stream candidates from a wordlist file.

        UTF-8 is attempted first, with replacement handling to avoid
        crashing on malformed laboratory wordlist files.
        """
        with open(
            wordlist_path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as wordlist:
            yield from self.from_candidates(
                wordlist,
                mutate=mutate,
            )