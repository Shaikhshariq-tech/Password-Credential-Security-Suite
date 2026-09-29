"""
Tests for the advanced offline attack simulation subsystem.
"""

from core.hash_utils import hash_password
from core.attack_engine import OfflineAttackEngine
from modules.brute_force_simulator import (
    BruteForceConfig,
    BruteForceSimulator,
)
from modules.crack_time_estimator import CrackTimeEstimator


def test_attack_engine_finds_password():
    """Engine should find a supplied laboratory password."""
    password = "LabPassword123!"
    target_hash = hash_password(password, "sha256")

    engine = OfflineAttackEngine(
        target_hash=target_hash,
        algorithm="sha256",
        attempt_limit=100,
    )

    candidates = [
        "password",
        "admin123",
        password,
        "another-password",
    ]

    result = engine.run(
        candidates,
        attack_type="dictionary",
    )

    assert result.match_found is True
    assert result.matched_password == password
    assert result.status == "CRACKED"
    assert result.candidates_tested == 3


def test_attack_engine_reports_no_match():
    """Engine should correctly report an unsuccessful attack."""
    target_hash = hash_password(
        "CorrectPassword",
        "sha256",
    )

    engine = OfflineAttackEngine(
        target_hash=target_hash,
        algorithm="sha256",
        attempt_limit=10,
    )

    result = engine.run(
        ["one", "two", "three"],
        attack_type="dictionary",
    )

    assert result.match_found is False
    assert result.matched_password is None
    assert result.status == "NOT_CRACKED"
    assert result.candidates_tested == 3


def test_attack_limit_is_enforced():
    """Engine must stop when its safety limit is reached."""
    target_hash = hash_password(
        "not-in-list",
        "sha256",
    )

    engine = OfflineAttackEngine(
        target_hash=target_hash,
        algorithm="sha256",
        attempt_limit=3,
    )

    result = engine.run(
        ["one", "two", "three", "four", "five"],
        attack_type="dictionary",
    )

    assert result.candidates_tested == 3
    assert result.status == "LIMIT_REACHED"
    assert result.termination_reason == "attempt_limit_reached"


def test_brute_force_search_space():
    """Verify theoretical brute-force search-space calculation."""
    search_space = BruteForceSimulator.calculate_search_space(
        character_count=2,
        minimum_length=1,
        maximum_length=3,
    )

    # 2^1 + 2^2 + 2^3 = 14
    assert search_space == 14


def test_brute_force_finds_single_character_password():
    """Brute-force simulator should find a controlled test password."""
    password = "b"
    target_hash = hash_password(password, "md5")

    simulator = BruteForceSimulator(
        target_hash=target_hash,
        algorithm="md5",
        attempt_limit=100,
    )

    config = BruteForceConfig(
        minimum_length=1,
        maximum_length=1,
        use_lowercase=True,
        use_uppercase=False,
        use_digits=False,
        use_symbols=False,
    )

    result = simulator.run(config)

    assert result.match_found is True
    assert result.matched_password == password
    assert result.status == "CRACKED"


def test_crack_time_estimator():
    """Verify crack-time calculations."""
    estimator = CrackTimeEstimator(
        attempts_per_second=10,
    )

    result = estimator.estimate(100)

    assert result.worst_case_seconds == 10
    assert result.average_case_seconds == 5
    assert result.average_case_attempts == 50


def test_crack_time_human_format():
    """Verify human-readable duration formatting."""
    assert CrackTimeEstimator.format_duration(1) == "1 second"
    assert CrackTimeEstimator.format_duration(60) == "1 minute"
    assert CrackTimeEstimator.format_duration(3600) == "1 hour"


def test_result_serialization():
    """Attack results should serialize cleanly."""
    password = "test"
    target_hash = hash_password(password, "sha256")

    engine = OfflineAttackEngine(
        target_hash=target_hash,
        algorithm="sha256",
        attempt_limit=10,
    )

    result = engine.run(
        ["test"],
        attack_type="dictionary",
    )

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["status"] == "CRACKED"
    assert data["matched_password"] == "test"
    assert "candidates_per_second" in data
    assert "termination_reason" in data