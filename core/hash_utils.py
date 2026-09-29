"""
Hashing utilities for controlled password-security simulations.
"""

import hashlib

from config.settings import SUPPORTED_HASH_ALGORITHMS


def normalize_algorithm(algorithm: str) -> str:
    """
    Normalize a hashing algorithm name.

    Example:
        SHA256 -> sha256
        sha-256 -> sha256
    """
    normalized = algorithm.strip().lower().replace("-", "")

    aliases = {
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
    }

    if normalized not in aliases:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    return aliases[normalized]


def hash_password(password: str, algorithm: str = "sha256") -> str:
    """
    Hash a password using a supported algorithm.

    This function is intended for controlled laboratory testing.
    """
    algorithm = normalize_algorithm(algorithm)

    password_bytes = password.encode("utf-8")
    hash_object = hashlib.new(algorithm, password_bytes)

    return hash_object.hexdigest()


def identify_hash_format(hash_value: str) -> list[str]:
    """
    Return possible algorithms based on the hexadecimal hash length.

    Length alone cannot prove the algorithm, so the function returns
    possible formats rather than claiming certainty.
    """
    value = hash_value.strip().lower()

    if not value:
        return []

    if any(character not in "0123456789abcdef" for character in value):
        return []

    length_mapping = {
        32: ["MD5"],
        40: ["SHA-1"],
        64: ["SHA-256"],
        128: ["SHA-512"],
    }

    return length_mapping.get(len(value), [])


def verify_password(
    password: str,
    expected_hash: str,
    algorithm: str = "sha256",
) -> bool:
    """
    Check whether a candidate password produces the expected hash.
    """
    calculated_hash = hash_password(password, algorithm)

    return calculated_hash.lower() == expected_hash.strip().lower()


def get_supported_algorithms() -> dict[str, str]:
    """Return supported hashing algorithms."""
    return SUPPORTED_HASH_ALGORITHMS.copy()