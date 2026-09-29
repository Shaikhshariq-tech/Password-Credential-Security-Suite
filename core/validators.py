"""
Validation helpers used throughout the application.
"""

from config.settings import MAX_SIMULATION_ATTEMPTS


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate a password supplied to the laboratory tools.
    """
    if not isinstance(password, str):
        return False, "Password must be text."

    if not password:
        return False, "Password cannot be empty."

    return True, "Valid password."


def validate_hash(hash_value: str) -> tuple[bool, str]:
    """
    Perform basic validation of a hexadecimal hash string.
    """
    if not isinstance(hash_value, str):
        return False, "Hash must be text."

    value = hash_value.strip()

    if not value:
        return False, "Hash cannot be empty."

    if any(character not in "0123456789abcdefABCDEF" for character in value):
        return False, "Hash contains non-hexadecimal characters."

    return True, "Valid hexadecimal hash."


def validate_algorithm(algorithm: str, supported: dict) -> tuple[bool, str]:
    """Validate a requested hashing algorithm."""
    normalized = algorithm.strip().lower().replace("-", "")

    if normalized not in supported:
        available = ", ".join(supported.keys())
        return False, f"Unsupported algorithm. Available: {available}"

    return True, "Valid algorithm."


def validate_attempt_limit(limit: int) -> tuple[bool, str]:
    """
    Prevent accidentally enormous laboratory simulations.
    """
    if not isinstance(limit, int):
        return False, "Attempt limit must be an integer."

    if limit <= 0:
        return False, "Attempt limit must be greater than zero."

    if limit > MAX_SIMULATION_ATTEMPTS:
        return (
            False,
            f"Attempt limit cannot exceed {MAX_SIMULATION_ATTEMPTS:,}.",
        )

    return True, "Valid attempt limit."