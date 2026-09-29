"""
Advanced offline attack engine for controlled password-security testing.

This module performs candidate-vs-hash comparisons only. It does not
attempt authentication against accounts, systems, or network services.
"""

from dataclasses import dataclass, field
from time import perf_counter
from typing import Iterable

from config.settings import MAX_SIMULATION_ATTEMPTS, DEFAULT_ATTEMPTS_PER_SECOND
from core.hash_utils import hash_password, normalize_algorithm
from core.validators import validate_attempt_limit


@dataclass
class AttackResult:
    """Structured result produced by an offline attack simulation."""

    attack_type: str
    algorithm: str
    target_hash: str
    candidates_tested: int
    match_found: bool
    matched_password: str | None
    elapsed_seconds: float
    candidates_per_second: float
    estimated_search_space: int
    estimated_total_seconds: float
    attempt_limit: int
    termination_reason: str
    status: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize the result into a dictionary."""
        return {
            "attack_type": self.attack_type,
            "algorithm": self.algorithm,
            "target_hash": self.target_hash,
            "candidates_tested": self.candidates_tested,
            "match_found": self.match_found,
            "matched_password": self.matched_password,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "candidates_per_second": round(self.candidates_per_second, 2),
            "estimated_search_space": self.estimated_search_space,
            "estimated_total_seconds": round(
                self.estimated_total_seconds,
                4,
            ),
            "attempt_limit": self.attempt_limit,
            "termination_reason": self.termination_reason,
            "status": self.status,
            "metadata": self.metadata,
        }


class OfflineAttackEngine:
    """
    Core engine for controlled offline password testing.

    Candidates are supplied by the caller and compared against a target
    password hash locally.
    """

    def __init__(
        self,
        target_hash: str,
        algorithm: str = "sha256",
        attempt_limit: int = MAX_SIMULATION_ATTEMPTS,
    ):
        self.target_hash = target_hash.strip().lower()
        self.algorithm = normalize_algorithm(algorithm)

        valid, message = validate_attempt_limit(attempt_limit)
        if not valid:
            raise ValueError(message)

        self.attempt_limit = attempt_limit

    def _estimate_seconds(
        self,
        search_space: int,
        rate: float,
    ) -> float:
        """Estimate how long a complete search space would take."""
        if rate <= 0:
            return 0.0

        return search_space / rate

    def run(
        self,
        candidates: Iterable[str],
        attack_type: str = "offline",
        estimated_search_space: int | None = None,
        metadata: dict | None = None,
    ) -> AttackResult:
        """
        Execute a bounded offline candidate attack.

        The candidate iterable is consumed locally and each candidate is
        compared against the supplied target hash.
        """
        start_time = perf_counter()

        tested = 0
        matched_password = None
        termination_reason = "candidate_exhausted"

        for candidate in candidates:
            if tested >= self.attempt_limit:
                termination_reason = "attempt_limit_reached"
                break

            if not isinstance(candidate, str):
                continue

            tested += 1

            if (
                hash_password(candidate, self.algorithm)
                == self.target_hash
            ):
                matched_password = candidate
                termination_reason = "match_found"
                break

        elapsed = perf_counter() - start_time

        if tested > 0 and elapsed > 0:
            rate = tested / elapsed
        else:
            rate = 0.0

        if estimated_search_space is None:
            estimated_search_space = tested

        estimated_seconds = self._estimate_seconds(
            estimated_search_space,
            DEFAULT_ATTEMPTS_PER_SECOND,
        )

        if matched_password is not None:
            status = "CRACKED"
        elif termination_reason == "attempt_limit_reached":
            status = "LIMIT_REACHED"
        else:
            status = "NOT_CRACKED"

        return AttackResult(
            attack_type=attack_type,
            algorithm=self.algorithm,
            target_hash=self.target_hash,
            candidates_tested=tested,
            match_found=matched_password is not None,
            matched_password=matched_password,
            elapsed_seconds=elapsed,
            candidates_per_second=rate,
            estimated_search_space=estimated_search_space,
            estimated_total_seconds=estimated_seconds,
            attempt_limit=self.attempt_limit,
            termination_reason=termination_reason,
            status=status,
            metadata=metadata or {},
        )