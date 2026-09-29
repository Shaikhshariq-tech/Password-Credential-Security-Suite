"""
End-to-end controlled laboratory workflow tests.
"""

import json
from pathlib import Path

from core.hash_utils import hash_password
from core.lab_workflow import LabWorkflow


LAB_PASSWORD = "LabPassword123!"


def test_complete_dictionary_audit_workflow(tmp_path):
    """
    Verify:

    password
        -> hash
        -> hash analysis
        -> wordlist
        -> dictionary simulation
        -> audit report
    """

    workflow = LabWorkflow()

    target_hash = hash_password(
        LAB_PASSWORD,
        "sha256",
    )

    password_analysis = workflow.analyze_password(
        LAB_PASSWORD
    )

    hash_analysis = workflow.analyze_hash(
        target_hash
    )

    wordlist = tmp_path / "lab_dictionary.txt"

    wordlist.write_text(
        "\n".join(
            [
                "password",
                "admin",
                "security",
                "security123",
                LAB_PASSWORD,
            ]
        ),
        encoding="utf-8",
    )

    attack_result = workflow.dictionary_attack_wordlist(
        target_hash=target_hash,
        algorithm="sha256",
        wordlist_path=wordlist,
        mutate=False,
        attempt_limit=100,
    )

    report = workflow.build_audit(
        target_hash=target_hash,
        algorithm="sha256",
        password=LAB_PASSWORD,
        attack_results=[attack_result],
    )

    assert password_analysis is not None
    assert hash_analysis is not None

    attack_data = attack_result.to_dict()

    assert attack_data["match_found"] is True
    assert attack_data["matched_password"] == LAB_PASSWORD

    report_data = report.to_dict()

    assert report_data["target"]["algorithm"] == "sha256"
    assert report_data["password_analysis"] is not None
    assert report_data["hash_analysis"] is not None
    assert len(report_data["attack_results"]) == 1


def test_complete_report_generation(tmp_path):
    """Verify JSON and text reports are generated from a real audit."""

    workflow = LabWorkflow()

    password = LAB_PASSWORD

    target_hash = hash_password(
        password,
        "sha256",
    )

    attack_result = workflow.dictionary_attack(
        target_hash=target_hash,
        algorithm="sha256",
        candidates=[
            "password",
            "admin",
            password,
        ],
        mutate=False,
        attempt_limit=100,
    )

    report = workflow.build_audit(
        target_hash=target_hash,
        algorithm="sha256",
        password=password,
        attack_results=[attack_result],
    )

    output_stem = tmp_path / "lab_audit"

    json_path, text_path = workflow.write_audit_report(
        report,
        output_stem=str(output_stem),
    )

    assert Path(json_path).exists()
    assert Path(text_path).exists()

    json_content = Path(json_path).read_text(
        encoding="utf-8"
    )

    text_content = Path(text_path).read_text(
        encoding="utf-8"
    )

    # Validate the JSON as structured data rather than
    # searching for arbitrary display text.
    json_data = json.loads(json_content)

    assert "metadata" in json_data
    assert "audit_id" in json_data["metadata"]
    assert json_data["metadata"]["audit_id"].startswith("AUD-")

    assert "target" in json_data
    assert json_data["target"]["algorithm"] == "sha256"

    assert (
        json_data["password_analysis"] is not None
    )

    assert (
        json_data["attack_results"][0]["match_found"]
        is True
    )

    assert (
        json_data["attack_results"][0]["matched_password"]
        == LAB_PASSWORD
    )

    assert LAB_PASSWORD in json_content

    # The text report is intended for human-readable
    # presentation, so verify its display headings.
    assert "PASSWORD & CREDENTIAL SECURITY AUDIT REPORT" in (
        text_content
    )

    assert "AUDIT INFORMATION" in text_content
    assert "PASSWORD ANALYSIS" in text_content
    assert "HASH ANALYSIS" in text_content
    assert "ATTACK SIMULATION RESULTS" in text_content
    assert LAB_PASSWORD in text_content