"""
Advanced hash-format and password-storage security analyzer.

This module performs identification and defensive analysis of
user-supplied offline hash strings.

Format identification is heuristic. A hash length alone does not
prove which algorithm produced it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class HashAnalysis:
    """Structured hash-analysis result."""

    input_hash: str
    possible_algorithms: list[str]
    format_type: str
    confidence: str
    length: int
    hexadecimal: bool
    salted_format: bool
    security_rating: str
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-compatible representation."""
        return {
            "input_hash": self.input_hash,
            "possible_algorithms": self.possible_algorithms,
            "format_type": self.format_type,
            "confidence": self.confidence,
            "length": self.length,
            "hexadecimal": self.hexadecimal,
            "salted_format": self.salted_format,
            "security_rating": self.security_rating,
            "findings": self.findings,
            "recommendations": self.recommendations,
        }


class HashAnalyzer:
    """Analyze common password-hash representations."""

    HEX_LENGTHS = {
        32: ["MD5"],
        40: ["SHA-1"],
        64: ["SHA-256"],
        128: ["SHA-512"],
    }

    MODULAR_FORMATS = {
        "$1$": ("MD5-Crypt", "LEGACY"),
        "$2a$": ("bcrypt", "MODERN"),
        "$2b$": ("bcrypt", "MODERN"),
        "$2y$": ("bcrypt", "MODERN"),
        "$5$": ("SHA-256-Crypt", "LEGACY-MODERATE"),
        "$6$": ("SHA-512-Crypt", "MODERN-LEGACY"),
        "$argon2id$": ("Argon2id", "MODERN"),
        "$argon2i$": ("Argon2i", "MODERN"),
        "$argon2d$": ("Argon2d", "MODERN"),
        "$7$": ("scrypt-family", "MODERN"),
    }

    @staticmethod
    def _is_hex(value: str) -> bool:
        return bool(value) and bool(re.fullmatch(r"[0-9a-fA-F]+", value))

    def _analyze_modular(self, value: str) -> HashAnalysis | None:
        """Analyze modular crypt-style formats."""
        for prefix, (algorithm, rating) in self.MODULAR_FORMATS.items():
            if value.startswith(prefix):
                findings = [
                    f"Detected modular password-storage format associated with {algorithm}."
                ]

                recommendations = [
                    "Verify that the password hashing configuration uses an appropriate cost/work factor.",
                    "Prefer modern adaptive password hashing for new deployments.",
                ]

                if rating == "LEGACY":
                    findings.append(
                        "The identified format is considered legacy for modern password storage."
                    )
                    recommendations.append(
                        "Migrate legacy password hashes to a modern adaptive password-hashing scheme."
                    )

                return HashAnalysis(
                    input_hash=value,
                    possible_algorithms=[algorithm],
                    format_type="Modular crypt format",
                    confidence="HIGH",
                    length=len(value),
                    hexadecimal=False,
                    salted_format=True,
                    security_rating=rating,
                    findings=findings,
                    recommendations=recommendations,
                )

        return None

    def analyze(self, hash_value: str) -> HashAnalysis:
        """Perform hash-format analysis."""
        if not isinstance(hash_value, str):
            raise TypeError("Hash value must be a string.")

        value = hash_value.strip()

        if not value:
            raise ValueError("Hash value cannot be empty.")

        modular_result = self._analyze_modular(value)

        if modular_result:
            return modular_result

        hexadecimal = self._is_hex(value)
        possible_algorithms = self.HEX_LENGTHS.get(len(value), [])

        if not hexadecimal:
            return HashAnalysis(
                input_hash=value,
                possible_algorithms=[],
                format_type="Unknown / non-hexadecimal",
                confidence="LOW",
                length=len(value),
                hexadecimal=False,
                salted_format=False,
                security_rating="UNKNOWN",
                findings=[
                    "The supplied value does not match supported hexadecimal or modular formats."
                ],
                recommendations=[
                    "Verify the source format and document the password-storage scheme.",
                    "Avoid attempting to infer an algorithm solely from an arbitrary string.",
                ],
            )

        if not possible_algorithms:
            return HashAnalysis(
                input_hash=value,
                possible_algorithms=[],
                format_type="Unknown hexadecimal",
                confidence="LOW",
                length=len(value),
                hexadecimal=True,
                salted_format=False,
                security_rating="UNKNOWN",
                findings=[
                    "Hexadecimal value detected, but its length does not match the supported formats."
                ],
                recommendations=[
                    "Identify the originating password-storage system and algorithm.",
                    "Document whether salting, work factors, or an adaptive KDF are used.",
                ],
            )

        algorithm = possible_algorithms[0]

        security_rating = {
            "MD5": "WEAK",
            "SHA-1": "WEAK",
            "SHA-256": "MODERATE",
            "SHA-512": "MODERATE",
        }[algorithm]

        findings = [
            f"Possible {algorithm} representation detected from hexadecimal length.",
            "Plain fast cryptographic hashes are not ideal for password storage.",
        ]

        recommendations = [
            "Use an adaptive password-hashing function designed for password storage.",
            "Use unique salts for individual password records.",
            "Configure an appropriate work factor and review it periodically.",
        ]

        if algorithm in {"MD5", "SHA-1"}:
            findings.append(
                f"{algorithm} is unsuitable for modern password storage."
            )
            recommendations.append(
                "Migrate legacy password records to a modern adaptive password-hashing scheme."
            )

        return HashAnalysis(
            input_hash=value,
            possible_algorithms=possible_algorithms,
            format_type="Raw hexadecimal digest",
            confidence="MEDIUM",
            length=len(value),
            hexadecimal=True,
            salted_format=False,
            security_rating=security_rating,
            findings=findings,
            recommendations=recommendations,
        )


def analyze_hash(hash_value: str) -> HashAnalysis:
    """Convenience wrapper."""
    return HashAnalyzer().analyze(hash_value)