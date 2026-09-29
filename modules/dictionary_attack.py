"""
Advanced offline dictionary attack module.

This module tests candidates from controlled laboratory wordlists against
an explicitly supplied password hash.
"""

from pathlib import Path

from core.attack_engine import AttackResult, OfflineAttackEngine
from core.candidate_pipeline import CandidatePipeline
from modules.wordlist_loader import WordlistLoader


class DictionaryAttack:
    """
    Controlled offline dictionary attack.

    Supports:
    - direct wordlist attacks
    - mutation-enhanced attacks
    - candidate limits
    - wordlist statistics
    - structured attack results
    """

    def __init__(
        self,
        target_hash: str,
        algorithm: str = "sha256",
        attempt_limit: int = 100_000,
    ):
        self.engine = OfflineAttackEngine(
            target_hash=target_hash,
            algorithm=algorithm,
            attempt_limit=attempt_limit,
        )

        self.attempt_limit = attempt_limit

    def attack_candidates(
        self,
        candidates,
        mutate: bool = False,
    ) -> AttackResult:
        """Run an attack against an iterable of supplied candidates."""
        pipeline = CandidatePipeline(
            max_candidates=self.attempt_limit,
        )

        processed_candidates = pipeline.from_candidates(
            candidates,
            mutate=mutate,
        )

        return self.engine.run(
            candidates=processed_candidates,
            attack_type=(
                "dictionary_mutation"
                if mutate
                else "dictionary"
            ),
            metadata={
                "mutation_enabled": mutate,
                "source_type": "candidate_iterable",
            },
        )

    def attack_wordlist(
        self,
        wordlist_path: str | Path,
        mutate: bool = False,
    ) -> AttackResult:
        """Run an offline attack using a wordlist file."""
        loader = WordlistLoader(wordlist_path)

        pipeline = CandidatePipeline(
            max_candidates=self.attempt_limit,
        )

        candidates = pipeline.from_wordlist(
            str(wordlist_path),
            mutate=mutate,
        )

        stats = loader.analyze()

        return self.engine.run(
            candidates=candidates,
            attack_type=(
                "dictionary_mutation"
                if mutate
                else "dictionary"
            ),
            estimated_search_space=stats.unique_candidates,
            metadata={
                "mutation_enabled": mutate,
                "source_type": "wordlist",
                "wordlist": str(wordlist_path),
                "wordlist_statistics": stats.to_dict(),
            },
        )