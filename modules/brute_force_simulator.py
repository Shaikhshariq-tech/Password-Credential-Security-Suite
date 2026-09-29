"""
Controlled offline brute-force simulation.

This module generates synthetic candidate passwords locally and compares
their hashes against a supplied laboratory target. It does not perform
live authentication or remote credential attacks.
"""

from dataclasses import dataclass
from itertools import product
from typing import Iterator

from config.settings import (
    DIGITS,
    LOWERCASE,
    MAX_SIMULATION_ATTEMPTS,
    SYMBOLS,
    UPPERCASE,
)
from core.attack_engine import AttackResult, OfflineAttackEngine


@dataclass(frozen=True)
class BruteForceConfig:
    """Configuration for a controlled brute-force simulation."""

    minimum_length: int = 1
    maximum_length: int = 4
    use_lowercase: bool = True
    use_uppercase: bool = False
    use_digits: bool = False
    use_symbols: bool = False

    def character_set(self) -> str:
        """Return the configured brute-force character set."""

        characters = ""

        if self.use_lowercase:
            characters += LOWERCASE

        if self.use_uppercase:
            characters += UPPERCASE

        if self.use_digits:
            characters += DIGITS

        if self.use_symbols:
            characters += SYMBOLS

        return "".join(dict.fromkeys(characters))

    def search_space(self) -> int:
        """Return the theoretical number of candidates."""

        return BruteForceSimulator.calculate_search_space(
            character_count=len(self.character_set()),
            minimum_length=self.minimum_length,
            maximum_length=self.maximum_length,
        )


class BruteForceSimulator:
    """Run bounded offline brute-force simulations."""

    def __init__(
        self,
        target_hash: str,
        algorithm: str,
        attempt_limit: int = MAX_SIMULATION_ATTEMPTS,
    ) -> None:
        self.engine = OfflineAttackEngine(
            target_hash=target_hash,
            algorithm=algorithm,
            attempt_limit=attempt_limit,
        )

    @staticmethod
    def calculate_search_space(
        character_count: int,
        minimum_length: int,
        maximum_length: int,
    ) -> int:
        """Calculate the theoretical brute-force search space."""

        if character_count < 0:
            raise ValueError("character_count cannot be negative.")

        if minimum_length < 1:
            raise ValueError("minimum_length must be at least 1.")

        if maximum_length < minimum_length:
            raise ValueError(
                "maximum_length must be greater than or equal to "
                "minimum_length."
            )

        if character_count == 0:
            return 0

        return sum(
            character_count ** length
            for length in range(
                minimum_length,
                maximum_length + 1,
            )
        )

    @staticmethod
    def _validate_config(config: BruteForceConfig) -> None:
        """Validate brute-force configuration."""

        if config.minimum_length < 1:
            raise ValueError("minimum_length must be at least 1.")

        if config.maximum_length < config.minimum_length:
            raise ValueError(
                "maximum_length must be greater than or equal to "
                "minimum_length."
            )

        if not config.character_set():
            raise ValueError(
                "At least one character class must be enabled."
            )

    def generate_candidates(
        self,
        config: BruteForceConfig,
    ) -> Iterator[str]:
        """Lazily generate candidates from the supplied configuration."""

        self._validate_config(config)

        characters = config.character_set()

        for length in range(
            config.minimum_length,
            config.maximum_length + 1,
        ):
            for candidate_tuple in product(characters, repeat=length):
                yield "".join(candidate_tuple)

    def _execute(self, config: BruteForceConfig) -> AttackResult:
        """Execute an attack using an already-created configuration."""

        self._validate_config(config)

        candidates = self.generate_candidates(config)

        return self.engine.run(
            candidates=candidates,
            attack_type="brute_force",
            estimated_search_space=config.search_space(),
            metadata={
                "minimum_length": config.minimum_length,
                "maximum_length": config.maximum_length,
                "lowercase": config.use_lowercase,
                "uppercase": config.use_uppercase,
                "digits": config.use_digits,
                "symbols": config.use_symbols,
                "character_set_size": len(config.character_set()),
            },
        )

    def run(
        self,
        config: BruteForceConfig | None = None,
        *,
        min_length: int = 1,
        max_length: int = 4,
        lowercase: bool = True,
        uppercase: bool = False,
        digits: bool = False,
        symbols: bool = False,
    ) -> AttackResult:
        """
        Run a controlled brute-force simulation.

        Supports both established interfaces:

        1. Configuration object:
            simulator.run(config)

        2. Workflow/CLI parameters:
            simulator.run(
                min_length=1,
                max_length=4,
                lowercase=True,
                uppercase=False,
                digits=False,
                symbols=False,
            )
        """

        if config is not None:
            if not isinstance(config, BruteForceConfig):
                raise TypeError(
                    "config must be a BruteForceConfig instance."
                )

            return self._execute(config)

        config = BruteForceConfig(
            minimum_length=min_length,
            maximum_length=max_length,
            use_lowercase=lowercase,
            use_uppercase=uppercase,
            use_digits=digits,
            use_symbols=symbols,
        )

        return self._execute(config)

