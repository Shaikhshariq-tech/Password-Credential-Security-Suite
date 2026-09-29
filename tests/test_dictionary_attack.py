"""
Tests for the advanced dictionary attack pipeline.
"""

from pathlib import Path

from core.hash_utils import hash_password
from core.candidate_pipeline import CandidatePipeline
from modules.dictionary_attack import DictionaryAttack
from modules.wordlist_loader import WordlistLoader


def test_candidate_pipeline_removes_duplicates():
    """Pipeline should preserve order while removing duplicates."""
    pipeline = CandidatePipeline(max_candidates=10)

    candidates = pipeline.from_candidates(
        [
            "password",
            "admin",
            "password",
            "qwerty",
            "admin",
        ]
    )

    assert list(candidates) == [
        "password",
        "admin",
        "qwerty",
    ]


def test_candidate_pipeline_skips_blank_values():
    """Blank candidates should not reach the attack engine."""
    pipeline = CandidatePipeline(max_candidates=10)

    candidates = pipeline.from_candidates(
        [
            "",
            "   ",
            "password",
            None,
            "admin",
        ]
    )

    assert list(candidates) == [
        "password",
        "admin",
    ]


def test_candidate_pipeline_limit():
    """Pipeline must enforce its maximum candidate count."""
    pipeline = CandidatePipeline(max_candidates=3)

    candidates = pipeline.from_candidates(
        [
            "one",
            "two",
            "three",
            "four",
            "five",
        ]
    )

    assert list(candidates) == [
        "one",
        "two",
        "three",
    ]


def test_wordlist_loader(tmp_path: Path):
    """Wordlist loader should correctly analyze a test wordlist."""
    wordlist = tmp_path / "test.txt"

    wordlist.write_text(
        "password\n"
        "admin\n"
        "\n"
        "password\n"
        "qwerty\n",
        encoding="utf-8",
    )

    loader = WordlistLoader(wordlist)

    stats = loader.analyze()

    assert stats.total_lines == 5
    assert stats.usable_candidates == 4
    assert stats.blank_lines == 1
    assert stats.duplicate_candidates == 1
    assert stats.unique_candidates == 3


def test_wordlist_unique_loading(tmp_path: Path):
    """Unique loading should preserve first-seen ordering."""
    wordlist = tmp_path / "test.txt"

    wordlist.write_text(
        "alpha\n"
        "beta\n"
        "alpha\n"
        "gamma\n",
        encoding="utf-8",
    )

    loader = WordlistLoader(wordlist)

    assert loader.load_unique() == [
        "alpha",
        "beta",
        "gamma",
    ]


def test_dictionary_attack_finds_password(tmp_path: Path):
    """Dictionary attack should find a controlled laboratory password."""
    password = "LabPassword123!"
    target_hash = hash_password(password, "sha256")

    wordlist = tmp_path / "passwords.txt"

    wordlist.write_text(
        "password\n"
        "admin123\n"
        "LabPassword123!\n"
        "qwerty\n",
        encoding="utf-8",
    )

    attack = DictionaryAttack(
        target_hash=target_hash,
        algorithm="sha256",
        attempt_limit=100,
    )

    result = attack.attack_wordlist(wordlist)

    assert result.match_found is True
    assert result.matched_password == password
    assert result.status == "CRACKED"
    assert result.attack_type == "dictionary"
    assert result.candidates_tested == 3


def test_dictionary_attack_no_match(tmp_path: Path):
    """Dictionary attack should report an unsuccessful search."""
    target_hash = hash_password(
        "not-present",
        "sha256",
    )

    wordlist = tmp_path / "passwords.txt"

    wordlist.write_text(
        "password\n"
        "admin\n"
        "qwerty\n",
        encoding="utf-8",
    )

    attack = DictionaryAttack(
        target_hash=target_hash,
        algorithm="sha256",
        attempt_limit=100,
    )

    result = attack.attack_wordlist(wordlist)

    assert result.match_found is False
    assert result.matched_password is None
    assert result.status == "NOT_CRACKED"
    assert result.candidates_tested == 3


def test_dictionary_attack_metadata(tmp_path: Path):
    """Attack result should contain useful wordlist metadata."""
    target_hash = hash_password(
        "admin",
        "md5",
    )

    wordlist = tmp_path / "passwords.txt"

    wordlist.write_text(
        "password\n"
        "admin\n"
        "admin\n",
        encoding="utf-8",
    )

    attack = DictionaryAttack(
        target_hash=target_hash,
        algorithm="md5",
        attempt_limit=100,
    )

    result = attack.attack_wordlist(wordlist)

    assert result.match_found is True
    assert result.metadata["source_type"] == "wordlist"

    stats = result.metadata["wordlist_statistics"]

    assert stats["usable_candidates"] == 3
    assert stats["duplicate_candidates"] == 1
    assert stats["unique_candidates"] == 2