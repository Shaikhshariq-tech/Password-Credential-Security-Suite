"""
Automated tests for the advanced password intelligence modules.
"""

from modules.hash_analyzer import HashAnalyzer
from modules.mutation_engine import MutationConfig, MutationEngine
from modules.password_strength import PasswordStrengthAnalyzer


def test_common_password_detection():
    analyzer = PasswordStrengthAnalyzer()

    result = analyzer.analyze("password123")

    assert result.common_password is True
    assert result.security_score < 65
    assert result.strength in {"CRITICAL", "WEAK", "MODERATE"}


def test_short_password_detection():
    analyzer = PasswordStrengthAnalyzer()

    result = analyzer.analyze("abc123")

    assert result.password_length == 6
    assert result.predictability_score > 0
    assert len(result.findings) > 0


def test_keyboard_pattern_detection():
    analyzer = PasswordStrengthAnalyzer()

    result = analyzer.analyze("Qwerty123!")

    assert result.keyboard_pattern is True


def test_year_pattern_detection():
    analyzer = PasswordStrengthAnalyzer()

    result = analyzer.analyze("Winter2026!")

    assert result.year_pattern is True


def test_leetspeak_detection():
    analyzer = PasswordStrengthAnalyzer()

    result = analyzer.analyze("P@ssw0rd!")

    assert result.leetspeak_pattern is True


def test_stronger_password_has_higher_score():
    analyzer = PasswordStrengthAnalyzer()

    weak = analyzer.analyze("password123")
    strong = analyzer.analyze(
        "v7$Qm2!zL9#pR4@x"
    )

    assert strong.security_score > weak.security_score
    assert strong.entropy_bits > weak.entropy_bits


def test_password_result_serialization():
    analyzer = PasswordStrengthAnalyzer()

    result = analyzer.analyze("SecurityLab!2026")
    data = result.to_dict()

    assert isinstance(data, dict)
    assert "entropy_bits" in data
    assert "security_score" in data
    assert "recommendations" in data


def test_md5_detection():
    analyzer = HashAnalyzer()

    result = analyzer.analyze(
        "5f4dcc3b5aa765d61d8327deb882cf99"
    )

    assert "MD5" in result.possible_algorithms
    assert result.security_rating == "WEAK"


def test_sha256_detection():
    analyzer = HashAnalyzer()

    result = analyzer.analyze(
        "a" * 64
    )

    assert "SHA-256" in result.possible_algorithms


def test_sha512_detection():
    analyzer = HashAnalyzer()

    result = analyzer.analyze(
        "a" * 128
    )

    assert "SHA-512" in result.possible_algorithms


def test_bcrypt_detection():
    analyzer = HashAnalyzer()

    result = analyzer.analyze(
        "$2b$12$abcdefghijklmnopqrstuu"
    )

    assert result.possible_algorithms == ["bcrypt"]
    assert result.salted_format is True


def test_argon2_detection():
    analyzer = HashAnalyzer()

    result = analyzer.analyze(
        "$argon2id$v=19$m=65536,t=3,p=4$example"
    )

    assert result.possible_algorithms == ["Argon2id"]
    assert result.salted_format is True


def test_mutation_engine():
    engine = MutationEngine()

    candidates = engine.generate(
        ["security"],
        max_candidates=500,
    )

    assert "security" in candidates
    assert "Security" in candidates
    assert "SECURITY" in candidates
    assert any(candidate.startswith("security") for candidate in candidates)


def test_mutation_leetspeak():
    config = MutationConfig(
        case_variations=False,
        number_suffixes=False,
        symbol_suffixes=False,
        leetspeak=True,
        reversed_variant=False,
    )

    engine = MutationEngine(config)

    candidates = engine.generate(
        ["password"],
        max_candidates=100,
    )

    assert any(
        candidate != "password"
        and (
            "@" in candidate
            or "0" in candidate
            or "3" in candidate
            or "$" in candidate
        )
        for candidate in candidates
    )


def test_mutation_limit():
    engine = MutationEngine()

    candidates = engine.generate(
        ["security", "password", "administrator"],
        max_candidates=25,
    )

    assert len(candidates) <= 25