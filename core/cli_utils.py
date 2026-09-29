"""
Command-line interface utilities.

Provides safe, reusable input and display helpers for the
Password & Credential Security Audit Suite.
"""

from __future__ import annotations

from typing import Iterable


def print_section(title: str, width: int = 60) -> None:
    """Print a formatted section heading."""
    print()
    print("=" * width)
    print(title)
    print("=" * width)


def print_subsection(title: str, width: int = 60) -> None:
    """Print a formatted subsection heading."""
    print()
    print("-" * width)
    print(title)
    print("-" * width)


def prompt_non_empty(prompt: str) -> str:
    """Prompt until the user supplies a non-empty value."""
    while True:
        value = input(prompt).strip()

        if value:
            return value

        print("Input cannot be empty. Please try again.")


def prompt_int(
    prompt: str,
    minimum: int | None = None,
    maximum: int | None = None,
    default: int | None = None,
) -> int:
    """Prompt for an integer within an optional range."""

    while True:
        raw = input(prompt).strip()

        if not raw and default is not None:
            return default

        try:
            value = int(raw)
        except ValueError:
            print("Please enter a valid integer.")
            continue

        if minimum is not None and value < minimum:
            print(f"Value must be at least {minimum}.")
            continue

        if maximum is not None and value > maximum:
            print(f"Value must not exceed {maximum}.")
            continue

        return value


def prompt_yes_no(
    prompt: str,
    default: bool = False,
) -> bool:
    """Prompt for a yes/no response."""

    suffix = "[Y/n]" if default else "[y/N]"

    while True:
        raw = input(f"{prompt} {suffix}: ").strip().lower()

        if not raw:
            return default

        if raw in {"y", "yes"}:
            return True

        if raw in {"n", "no"}:
            return False

        print("Please enter Y or N.")


def choose_from_list(
    title: str,
    options: Iterable[tuple[str, str]],
) -> str:
    """
    Display choices and return the selected option key.

    Args:
        title: Menu title.
        options: Iterable of (key, display_name) pairs.
    """

    option_list = list(options)

    print_subsection(title)

    for key, label in option_list:
        print(f"[{key}] {label}")

    valid_keys = {key for key, _ in option_list}

    while True:
        choice = input("Select an option: ").strip()

        if choice in valid_keys:
            return choice

        print("Invalid selection. Please choose one of the displayed options.")


def print_key_value(
    label: str,
    value: object,
    width: int = 28,
) -> None:
    """Print a consistently aligned key/value pair."""
    print(f"{label:<{width}}: {value}")


def print_list(
    title: str,
    values: Iterable[object],
) -> None:
    """Print a titled bullet list."""

    print_subsection(title)

    items = list(values)

    if not items:
        print("  None")
        return

    for value in items:
        print(f"  - {value}")


def pause() -> None:
    """Pause until the user is ready to continue."""
    input("\nPress Enter to continue...")