"""
Advanced Password Strength Analysis Engine.

Designed for controlled credential-security assessment.

The analyzer evaluates:
- Character composition
- Entropy approximation
- Character-space size
- Common-password exposure
- Sequential patterns
- Repeated characters
- Keyboard patterns
- Date/year patterns
- Leetspeak
- Predictability
- Length
- Overall security score
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome1",
    "abc123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "master",
    "login",
    "root",
    "test",
    "guest",
    "changeme",
}

KEYBOARD_PATTERNS = (
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
)

LEET_REPLACEMENTS = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "@": "a",
    "$": "s",
    "5": "s",
    "7": "t",
    "+": "t",
}

SEQUENTIAL_PATTERNS = (
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "0123456789",
    "9876543210",
)


@dataclass
class PasswordAnalysis:
    """Structured result returned by the password analyzer."""

    password_length: int
    character_space: int
    entropy_bits: float

    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool

    unique_characters: int

    common_password: bool
    repeated_pattern: bool
    sequential_pattern: bool
    keyboard_pattern: bool
    year_pattern: bool
    leetspeak_pattern: bool

    predictability_score: float
    security_score: float
    strength: str

    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert the analysis result to a JSON-compatible dictionary."""
        return {
            "password_length": self.password_length,
            "character_space": self.character_space,
            "entropy_bits": round(self.entropy_bits, 2),
            "character_classes": {
                "lowercase": self.has_lowercase,
                "uppercase": self.has_uppercase,
                "digits": self.has_digits,
                "symbols": self.has_symbols,
            },
            "unique_characters": self.unique_characters,
            "patterns": {
                "common_password": self.common_password,
                "repeated_pattern": self.repeated_pattern,
                "sequential_pattern": self.sequential_pattern,
                "keyboard_pattern": self.keyboard_pattern,
                "year_pattern": self.year_pattern,
                "leetspeak_pattern": self.leetspeak_pattern,
            },
            "predictability_score": round(self.predictability_score, 2),
            "security_score": round(self.security_score, 2),
            "strength": self.strength,
            "findings": self.findings,
            "recommendations": self.recommendations,
        }


class PasswordStrengthAnalyzer:
    """Advanced password-security analyzer."""

    def __init__(self, common_passwords: set[str] | None = None) -> None:
        self.common_passwords = (
            common_passwords if common_passwords is not None else COMMON_PASSWORDS
        )

    @staticmethod
    def _character_space(password: str) -> int:
        """Estimate the character pool used by a password."""
        pool = 0

        if any(char.islower() for char in password):
            pool += 26

        if any(char.isupper() for char in password):
            pool += 26

        if any(char.isdigit() for char in password):
            pool += 10

        if any(not char.isalnum() for char in password):
            pool += 32

        return pool

    @staticmethod
    def _entropy(password: str, character_space: int) -> float:
        """
        Estimate theoretical entropy.

        This is an approximation of brute-force search-space entropy.
        Real-world password entropy can be substantially lower because
        humans select passwords non-randomly.
        """
        if not password or character_space <= 0:
            return 0.0

        return len(password) * math.log2(character_space)

    @staticmethod
    def _has_repeated_pattern(password: str) -> bool:
        """Detect obvious repeated-character structures."""
        if len(password) < 4:
            return False

        if len(set(password)) == 1:
            return True

        if re.search(r"(.)\1{2,}", password):
            return True

        half = len(password) // 2

        if len(password) % 2 == 0:
            if password[:half] == password[half:]:
                return True

        return False

    @staticmethod
    def _has_sequential_pattern(password: str) -> bool:
        """Detect ascending or descending sequences."""
        normalized = password.lower()

        for sequence in SEQUENTIAL_PATTERNS:
            for size in range(3, 6):
                for index in range(len(sequence) - size + 1):
                    if sequence[index : index + size] in normalized:
                        return True

        return False

    @staticmethod
    def _has_keyboard_pattern(password: str) -> bool:
        """Detect common keyboard-row sequences."""
        normalized = password.lower()

        return any(
            pattern in normalized
            for pattern in KEYBOARD_PATTERNS
        )

    @staticmethod
    def _has_year_pattern(password: str) -> bool:
        """Detect common four-digit year-like patterns."""
        years = re.findall(r"(19\d{2}|20\d{2})", password)

        return bool(years)

    @staticmethod
    def _has_leetspeak(password: str) -> bool:
        """
        Detect likely leetspeak substitutions.

        Example:
            p@ssw0rd
            s3cur1ty
        """
        normalized = password.lower()

        substitution_count = sum(
            normalized.count(symbol)
            for symbol in LEET_REPLACEMENTS
        )

        return substitution_count >= 1

    def _common_password_match(self, password: str) -> bool:
        """Check direct and simple normalized dictionary matches."""
        normalized = password.lower()

        if normalized in self.common_passwords:
            return True

        stripped = re.sub(r"[^a-z]", "", normalized)

        return stripped in self.common_passwords

    @staticmethod
    def _predictability_score(
        password: str,
        *,
        common_password: bool,
        repeated_pattern: bool,
        sequential_pattern: bool,
        keyboard_pattern: bool,
        year_pattern: bool,
        leetspeak_pattern: bool,
    ) -> float:
        """
        Calculate a 0-100 predictability score.

        Higher means more predictable.
        """
        score = 0.0

        if common_password:
            score += 45

        if repeated_pattern:
            score += 15

        if sequential_pattern:
            score += 15

        if keyboard_pattern:
            score += 15

        if year_pattern:
            score += 10

        if leetspeak_pattern:
            score += 5

        # Short passwords receive additional predictability penalty.
        if len(password) < 8:
            score += 10
        elif len(password) < 12:
            score += 4

        return min(score, 100.0)

    @staticmethod
    def _security_score(
        password: str,
        entropy: float,
        predictability: float,
        *,
        common_password: bool,
        repeated_pattern: bool,
        sequential_pattern: bool,
        keyboard_pattern: bool,
    ) -> float:
        """Calculate the final 0-100 security score."""
        score = 0.0

        # Length contribution.
        score += min(len(password) / 16 * 25, 25)

        # Entropy contribution.
        score += min(entropy / 80 * 40, 40)

        # Character diversity.
        classes = sum(
            [
                any(c.islower() for c in password),
                any(c.isupper() for c in password),
                any(c.isdigit() for c in password),
                any(not c.isalnum() for c in password),
            ]
        )

        score += classes * 5

        # Predictability reduces the score.
        score -= predictability * 0.20

        if common_password:
            score -= 20

        if repeated_pattern:
            score -= 8

        if sequential_pattern:
            score -= 8

        if keyboard_pattern:
            score -= 8

        return max(0.0, min(score, 100.0))

    @staticmethod
    def _strength_label(score: float) -> str:
        """Convert numerical score to a security classification."""
        if score < 25:
            return "CRITICAL"
        if score < 45:
            return "WEAK"
        if score < 65:
            return "MODERATE"
        if score < 80:
            return "STRONG"

        return "VERY STRONG"

    @staticmethod
    def _build_findings(
        password: str,
        *,
        common_password: bool,
        repeated_pattern: bool,
        sequential_pattern: bool,
        keyboard_pattern: bool,
        year_pattern: bool,
        leetspeak_pattern: bool,
    ) -> list[str]:
        """Generate human-readable security findings."""
        findings: list[str] = []

        if len(password) < 8:
            findings.append("Password is shorter than the recommended minimum.")

        if common_password:
            findings.append("Password appears in a common-password dataset.")

        if repeated_pattern:
            findings.append("Repeated-character or repeated-block pattern detected.")

        if sequential_pattern:
            findings.append("Sequential character pattern detected.")

        if keyboard_pattern:
            findings.append("Common keyboard pattern detected.")

        if year_pattern:
            findings.append("Four-digit year pattern detected.")

        if leetspeak_pattern:
            findings.append("Potential leetspeak substitution detected.")

        if not findings:
            findings.append("No major predictable pattern detected.")

        return findings

    @staticmethod
    def _build_recommendations(
        password: str,
        entropy: float,
        predictability: float,
    ) -> list[str]:
        """Generate password improvement recommendations."""
        recommendations: list[str] = []

        if len(password) < 12:
            recommendations.append(
                "Prefer a password or passphrase of at least 12-16 characters."
            )

        if entropy < 50:
            recommendations.append(
                "Increase password unpredictability and search-space size."
            )

        if predictability >= 40:
            recommendations.append(
                "Avoid common words, predictable patterns, dates, and substitutions."
            )

        if not any(char.isupper() for char in password):
            recommendations.append(
                "Consider using uppercase characters where appropriate."
            )

        if not any(char.isdigit() for char in password):
            recommendations.append(
                "Consider including digits where appropriate."
            )

        if not any(not char.isalnum() for char in password):
            recommendations.append(
                "Consider additional character diversity when required by policy."
            )

        recommendations.append(
            "Do not reuse passwords across different services."
        )

        return recommendations

    def analyze(self, password: str) -> PasswordAnalysis:
        """Perform complete password analysis."""
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        if not password:
            raise ValueError("Password cannot be empty.")

        character_space = self._character_space(password)
        entropy = self._entropy(password, character_space)

        common_password = self._common_password_match(password)
        repeated_pattern = self._has_repeated_pattern(password)
        sequential_pattern = self._has_sequential_pattern(password)
        keyboard_pattern = self._has_keyboard_pattern(password)
        year_pattern = self._has_year_pattern(password)
        leetspeak_pattern = self._has_leetspeak(password)

        predictability = self._predictability_score(
            password,
            common_password=common_password,
            repeated_pattern=repeated_pattern,
            sequential_pattern=sequential_pattern,
            keyboard_pattern=keyboard_pattern,
            year_pattern=year_pattern,
            leetspeak_pattern=leetspeak_pattern,
        )

        security_score = self._security_score(
            password,
            entropy,
            predictability,
            common_password=common_password,
            repeated_pattern=repeated_pattern,
            sequential_pattern=sequential_pattern,
            keyboard_pattern=keyboard_pattern,
        )

        strength = self._strength_label(security_score)

        findings = self._build_findings(
            password,
            common_password=common_password,
            repeated_pattern=repeated_pattern,
            sequential_pattern=sequential_pattern,
            keyboard_pattern=keyboard_pattern,
            year_pattern=year_pattern,
            leetspeak_pattern=leetspeak_pattern,
        )

        recommendations = self._build_recommendations(
            password,
            entropy,
            predictability,
        )

        return PasswordAnalysis(
            password_length=len(password),
            character_space=character_space,
            entropy_bits=entropy,
            has_lowercase=any(c.islower() for c in password),
            has_uppercase=any(c.isupper() for c in password),
            has_digits=any(c.isdigit() for c in password),
            has_symbols=any(not c.isalnum() for c in password),
            unique_characters=len(set(password)),
            common_password=common_password,
            repeated_pattern=repeated_pattern,
            sequential_pattern=sequential_pattern,
            keyboard_pattern=keyboard_pattern,
            year_pattern=year_pattern,
            leetspeak_pattern=leetspeak_pattern,
            predictability_score=predictability,
            security_score=security_score,
            strength=strength,
            findings=findings,
            recommendations=recommendations,
        )


def analyze_password(password: str) -> PasswordAnalysis:
    """Convenience wrapper around PasswordStrengthAnalyzer."""
    return PasswordStrengthAnalyzer().analyze(password)