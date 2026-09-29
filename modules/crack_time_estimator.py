"""
Advanced crack-time estimation utilities.

Estimates are educational approximations, not predictions of real-world
hardware performance.

The estimator supports two calculation modes:

1. Direct search-space estimation:
       estimate(search_space)

2. Password-parameter estimation:
       estimate(
           password_length=12,
           character_set_size=94,
           attempts_per_second=1_000_000,
       )

All calculations are theoretical and intended for controlled laboratory
security assessment.
"""

from dataclasses import dataclass
from typing import Optional

from config.settings import DEFAULT_ATTEMPTS_PER_SECOND


@dataclass
class CrackTimeEstimate:
    """Structured crack-time estimation result."""

    search_space: int
    attempts_per_second: float
    average_case_attempts: float
    worst_case_seconds: float
    average_case_seconds: float
    worst_case_human: str
    average_case_human: str

    @property
    def human_readable_worst_case(self) -> str:
        """Compatibility alias used by the CLI."""
        return self.worst_case_human

    @property
    def human_readable_average_case(self) -> str:
        """Compatibility alias used by the CLI."""
        return self.average_case_human

    def to_dict(self) -> dict:
        """Serialize the estimate."""
        return {
            "search_space": self.search_space,
            "attempts_per_second": self.attempts_per_second,
            "average_case_attempts": self.average_case_attempts,
            "worst_case_seconds": self.worst_case_seconds,
            "average_case_seconds": self.average_case_seconds,
            "worst_case_human": self.worst_case_human,
            "average_case_human": self.average_case_human,
            "human_readable_worst_case": self.human_readable_worst_case,
            "human_readable_average_case": (
                self.human_readable_average_case
            ),
        }


class CrackTimeEstimator:
    """
    Converts password search-space size into crack-time estimates.

    The estimator uses:

        search space = character_set_size ** password_length

        worst-case attempts = search space

        average-case attempts = search_space / 2

        worst-case time = search_space / attempts_per_second

        average-case time = average_case_attempts / attempts_per_second

    These are theoretical estimates only.
    """

    def __init__(
        self,
        attempts_per_second: float = DEFAULT_ATTEMPTS_PER_SECOND,
    ):
        if attempts_per_second <= 0:
            raise ValueError(
                "Attempts per second must be greater than zero."
            )

        self.attempts_per_second = float(attempts_per_second)

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Convert seconds into a readable duration."""
        if seconds < 0:
            raise ValueError("Duration cannot be negative.")

        if seconds < 1:
            return f"{seconds:.3f} seconds"

        units = (
            ("year", 31_536_000),
            ("day", 86_400),
            ("hour", 3_600),
            ("minute", 60),
            ("second", 1),
        )

        remaining = float(seconds)
        parts = []

        for name, size in units:
            value = int(remaining // size)

            if value:
                remaining -= value * size
                suffix = "" if value == 1 else "s"
                parts.append(f"{value} {name}{suffix}")

            if len(parts) >= 2:
                break

        return ", ".join(parts) if parts else "0 seconds"

    def estimate(
        self,
        search_space: Optional[int] = None,
        *,
        password_length: Optional[int] = None,
        character_set_size: Optional[int] = None,
        attempts_per_second: Optional[float] = None,
    ) -> CrackTimeEstimate:
        """
        Calculate average and worst-case search duration.

        The method supports either:

            estimate(search_space)

        or:

            estimate(
                password_length=12,
                character_set_size=94,
                attempts_per_second=1_000_000,
            )

        When password parameters are supplied, the search space is:

            character_set_size ** password_length

        ``attempts_per_second`` supplied to this method overrides the
        estimator's configured default for this calculation only.
        """

        supplied_parameter_mode = (
            password_length is not None
            or character_set_size is not None
        )

        if supplied_parameter_mode:
            if password_length is None:
                raise ValueError(
                    "Password length is required when using "
                    "character-set size."
                )

            if character_set_size is None:
                raise ValueError(
                    "Character-set size is required when using "
                    "password length."
                )

            if password_length <= 0:
                raise ValueError(
                    "Password length must be greater than zero."
                )

            if character_set_size <= 0:
                raise ValueError(
                    "Character-set size must be greater than zero."
                )

            if search_space is not None:
                raise ValueError(
                    "Provide either search_space or password parameters, "
                    "not both."
                )

            search_space = character_set_size ** password_length

        elif search_space is None:
            raise ValueError(
                "Search space or password parameters must be provided."
            )

        if search_space < 0:
            raise ValueError(
                "Search space cannot be negative."
            )

        rate = (
            self.attempts_per_second
            if attempts_per_second is None
            else float(attempts_per_second)
        )

        if rate <= 0:
            raise ValueError(
                "Attempts per second must be greater than zero."
            )

        worst_case_seconds = search_space / rate

        average_case_attempts = search_space / 2

        average_case_seconds = average_case_attempts / rate

        return CrackTimeEstimate(
            search_space=search_space,
            attempts_per_second=rate,
            average_case_attempts=average_case_attempts,
            worst_case_seconds=worst_case_seconds,
            average_case_seconds=average_case_seconds,
            worst_case_human=self.format_duration(
                worst_case_seconds
            ),
            average_case_human=self.format_duration(
                average_case_seconds
            ),
        )

    def estimate_brute_force(
        self,
        character_set_size: int,
        minimum_length: int,
        maximum_length: int,
    ) -> CrackTimeEstimate:
        """Estimate brute-force duration across a length range."""
        if character_set_size <= 0:
            raise ValueError(
                "Character-set size must be greater than zero."
            )

        if minimum_length <= 0:
            raise ValueError(
                "Minimum length must be greater than zero."
            )

        if maximum_length < minimum_length:
            raise ValueError(
                "Maximum length cannot be smaller than minimum length."
            )

        search_space = sum(
            character_set_size**length
            for length in range(
                minimum_length,
                maximum_length + 1,
            )
        )

        return self.estimate(search_space)