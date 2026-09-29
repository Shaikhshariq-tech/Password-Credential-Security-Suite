"""
High-level controlled laboratory workflow orchestration.
"""

from pathlib import Path
from typing import Any, Iterable

from config.settings import REPORT_DIR
from modules.brute_force_simulator import BruteForceSimulator
from modules.dictionary_attack import DictionaryAttack
from modules.hash_analyzer import HashAnalyzer
from modules.mutation_engine import MutationEngine
from modules.password_strength import PasswordStrengthAnalyzer
from reporting.audit_builder import AuditBuilder
from reporting.report_writer import ReportWriter


class LabWorkflow:
    """Coordinate analysis, attack simulation, and reporting workflows."""

    def __init__(self) -> None:
        self.password_analyzer = PasswordStrengthAnalyzer()
        self.hash_analyzer = HashAnalyzer()
        self.mutation_engine = MutationEngine()

    def analyze_password(self, password: str) -> Any:
        """Analyze password strength and predictability."""
        return self.password_analyzer.analyze(password)

    def analyze_hash(self, target_hash: str) -> Any:
        """Analyze a supplied offline hash."""
        return self.hash_analyzer.analyze(target_hash)

    def generate_hash(
        self,
        password: str,
        algorithm: str,
    ) -> str:
        """Generate a hash for a controlled laboratory password."""
        from core.hash_utils import hash_password

        return hash_password(password, algorithm)

    def generate_mutations(
        self,
        candidates: Iterable[str],
        max_candidates: int | None = None,
    ) -> list[str]:
        """Generate deterministic mutations from supplied candidates."""
        if max_candidates is None:
            return self.mutation_engine.generate(candidates)

        return self.mutation_engine.generate(
            candidates,
            max_candidates=max_candidates,
        )

    def load_wordlist(
        self,
        wordlist_path: str | Path,
    ) -> list[str]:
        """Load candidates from a wordlist."""
        from modules.wordlist_loader import WordlistLoader

        loader = WordlistLoader(wordlist_path)
        return loader.load_unique()

    def dictionary_attack(
        self,
        target_hash: str,
        algorithm: str,
        candidates: Iterable[str],
        mutate: bool = False,
        attempt_limit: int = 100_000,
    ) -> Any:
        """Run a controlled offline dictionary attack simulation."""

        attack = DictionaryAttack(
            target_hash=target_hash,
            algorithm=algorithm,
            attempt_limit=attempt_limit,
        )

        return attack.attack_candidates(
            candidates,
            mutate=mutate,
        )

    def dictionary_attack_wordlist(
        self,
        target_hash: str,
        algorithm: str,
        wordlist_path: str | Path,
        mutate: bool = False,
        attempt_limit: int = 100_000,
    ) -> Any:
        """Run a dictionary attack against a supplied wordlist."""

        attack = DictionaryAttack(
            target_hash=target_hash,
            algorithm=algorithm,
            attempt_limit=attempt_limit,
        )

        return attack.attack_wordlist(
            wordlist_path,
            mutate=mutate,
        )

    def brute_force_attack(
        self,
        target_hash: str,
        algorithm: str,
        min_length: int,
        max_length: int,
        lowercase: bool = True,
        uppercase: bool = False,
        digits: bool = False,
        symbols: bool = False,
        attempt_limit: int = 100_000,
    ) -> Any:
        """Run a controlled brute-force simulation."""

        attack = BruteForceSimulator(
            target_hash=target_hash,
            algorithm=algorithm,
            attempt_limit=attempt_limit,
        )

        return attack.run(
            min_length=min_length,
            max_length=max_length,
            lowercase=lowercase,
            uppercase=uppercase,
            digits=digits,
            symbols=symbols,
        )

    def estimate_crack_time(
        self,
        password_length: int,
        character_set_size: int,
        attempts_per_second: int,
    ) -> Any:
        """Estimate brute-force search time."""
        from modules.crack_time_estimator import CrackTimeEstimator

        estimator = CrackTimeEstimator()

        return estimator.estimate(
            password_length=password_length,
            character_set_size=character_set_size,
            attempts_per_second=attempts_per_second,
        )

    def build_audit(
        self,
        target_hash: str,
        algorithm: str,
        password: str | None = None,
        attack_results: list[Any] | None = None,
    ) -> Any:
        """Build a complete security audit from supplied lab data."""

        builder = AuditBuilder(
            target_hash=target_hash,
            algorithm=algorithm,
        )

        if password is not None:
            password_analysis = self.analyze_password(password)
            builder.add_password_analysis(password_analysis)

        hash_analysis = self.analyze_hash(target_hash)
        builder.add_hash_analysis(hash_analysis)

        for result in attack_results or []:
            builder.add_attack_result(result)

        return builder.build()

    def write_audit_report(
        self,
        report: Any,
        output_stem: str | None = None,
    ) -> tuple[Path, Path]:
        """Write both JSON and human-readable audit reports."""

        if output_stem is None:
            output_directory = REPORT_DIR
        else:
            output_directory = Path(output_stem).parent

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        writer = ReportWriter(
            output_directory=output_directory,
        )

        return writer.write_both(report)

    @property
    def attack_engine(self) -> Any:
        """Expose the offline attack engine when required by callers."""
        from core.attack_engine import OfflineAttackEngine

        return OfflineAttackEngine