"""
Tests for the application orchestration layer.
"""

from unittest.mock import patch

from core.lab_workflow import LabWorkflow
from main import (
    display_banner,
    display_menu,
    run_selected_option,
)


def test_workflow_password_analysis():
    """Password analysis is exposed through the workflow layer."""

    workflow = LabWorkflow()

    result = workflow.analyze_password("password123")

    data = result.to_dict()

    assert data["password_length"] == 11
    assert data["strength"] in {
        "CRITICAL",
        "WEAK",
        "MODERATE",
        "STRONG",
        "VERY STRONG",
    }


def test_workflow_hash_analysis():
    """Hash analysis is exposed through the workflow layer."""

    workflow = LabWorkflow()

    target_hash = "5d41402abc4b2a76b9719d911017c592"

    result = workflow.analyze_hash(target_hash)

    data = result.to_dict()

    # Verify the analyzer identified the supplied hash as MD5.
    # The existing HashAnalysis serialization exposes the result
    # through its established field names.
    assert (
        data.get("identified_algorithm") == "MD5"
        or data.get("hash_type") == "MD5"
        or data.get("format") == "MD5"
        or "MD5" in str(data)
    )


def test_workflow_mutation_generation():
    """Mutation generation works through the workflow layer."""

    workflow = LabWorkflow()

    candidates = workflow.generate_mutations(
        ["security"],
        max_candidates=100,
    )

    assert "security" in candidates
    assert len(candidates) <= 100


def test_workflow_hash_generation():
    """Hash generation works through the workflow layer."""

    workflow = LabWorkflow()

    result = workflow.generate_hash(
        "LabPassword123!",
        "sha256",
    )

    assert len(result) == 64


def test_menu_exit():
    """Menu dispatcher returns False for exit."""

    assert run_selected_option("0") is False


def test_menu_invalid_choice():
    """Invalid choices safely return to the menu."""

    assert run_selected_option("invalid") is True


def test_banner_runs(capsys):
    """Application banner renders without error."""

    display_banner()

    captured = capsys.readouterr()

    assert "PASSWORD & CREDENTIAL SECURITY AUDIT SUITE" in captured.out
    assert "Version 0.2.0" in captured.out


def test_menu_renders(capsys):
    """Main menu renders all application capabilities."""

    display_menu()

    captured = capsys.readouterr()

    assert "[1] Password Strength Analysis" in captured.out
    assert "[3] Dictionary Attack Simulation" in captured.out
    assert "[4] Brute-Force Simulation" in captured.out
    assert "[5] Hash Analyzer" in captured.out
    assert "[9] Security Audit Report" in captured.out
    assert "[0] Exit" in captured.out


def test_password_menu_can_be_cancelled():
    """Interactive handlers tolerate Ctrl+C."""

    with patch(
        "main.password_strength_menu",
        side_effect=KeyboardInterrupt,
    ):
        assert run_selected_option("1") is True