"""
Tests for the unified audit and reporting subsystem.
"""

import json
from pathlib import Path

from core.hash_utils import hash_password
from core.attack_engine import OfflineAttackEngine
from modules.password_strength import analyze_password
from modules.hash_analyzer import HashAnalyzer
from reporting.audit_builder import AuditBuilder
from reporting.report_writer import ReportWriter


def test_audit_builder_creates_report():
    """Builder should produce a complete structured report."""
    password = "password123"
    target_hash = hash_password(password, "sha256")

    builder = AuditBuilder(
        target_hash=target_hash,
        algorithm="sha256",
    )

    hash_analyzer = HashAnalyzer()

    report = (
        builder
        .add_password_analysis(
            analyze_password(password)
        )
        .add_hash_analysis(
            hash_analyzer.analyze(target_hash)
        )
        .build()
    )

    data = report.to_dict()

    assert "metadata" in data
    assert "target" in data
    assert "password_analysis" in data
    assert "hash_analysis" in data
    assert "findings" in data
    assert "recommendations" in data
    assert "risk_level" in data


def test_audit_detects_weak_password():
    """Weak password analysis should produce a security finding."""
    password = "password123"
    target_hash = hash_password(password, "sha256")

    builder = AuditBuilder(
        target_hash=target_hash,
        algorithm="sha256",
    )

    report = (
        builder
        .add_password_analysis(
            analyze_password(password)
        )
        .build()
    )

    assert len(report.findings) >= 1
    assert report.risk_level in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


def test_audit_records_attack_result():
    """Attack results should appear in the final report."""
    password = "admin"
    target_hash = hash_password(password, "md5")

    engine = OfflineAttackEngine(
        target_hash=target_hash,
        algorithm="md5",
        attempt_limit=10,
    )

    result = engine.run(
        ["password", "admin"],
        attack_type="dictionary",
    )

    builder = AuditBuilder(
        target_hash=target_hash,
        algorithm="md5",
    )

    report = (
        builder
        .add_attack_result(result)
        .build()
    )

    assert len(report.attack_results) == 1
    assert report.attack_results[0]["status"] == "CRACKED"
    assert report.risk_level == "HIGH"


def test_audit_contains_attack_finding():
    """A recovered password should create a finding."""
    password = "admin"
    target_hash = hash_password(password, "md5")

    engine = OfflineAttackEngine(
        target_hash=target_hash,
        algorithm="md5",
        attempt_limit=10,
    )

    result = engine.run(
        ["admin"],
        attack_type="dictionary",
    )

    builder = AuditBuilder(
        target_hash=target_hash,
        algorithm="md5",
    )

    report = (
        builder
        .add_attack_result(result)
        .build()
    )

    titles = [
        finding.title
        for finding in report.findings
    ]

    assert (
        "Password recovered during offline simulation"
        in titles
    )


def test_report_writer_json(tmp_path: Path):
    """JSON writer should create valid structured JSON."""
    password = "TestPassword"
    target_hash = hash_password(password, "sha256")

    report = (
        AuditBuilder(
            target_hash=target_hash,
            algorithm="sha256",
        )
        .build()
    )

    writer = ReportWriter(tmp_path)

    path = writer.write_json(
        report,
        "audit.json",
    )

    assert path.exists()

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    assert data["target"]["hash"] == target_hash
    assert data["target"]["algorithm"] == "sha256"


def test_report_writer_text(tmp_path: Path):
    """Text writer should create a readable report."""
    target_hash = hash_password(
        "TestPassword",
        "sha256",
    )

    report = (
        AuditBuilder(
            target_hash=target_hash,
            algorithm="sha256",
        )
        .build()
    )

    writer = ReportWriter(tmp_path)

    path = writer.write_text(
        report,
        "audit.txt",
    )

    assert path.exists()

    content = path.read_text(
        encoding="utf-8"
    )

    assert (
        "PASSWORD & CREDENTIAL SECURITY AUDIT REPORT"
        in content
    )

    assert "OVERALL RISK" in content
    assert target_hash in content


def test_report_writer_both_formats(tmp_path: Path):
    """write_both should generate JSON and text reports."""
    target_hash = hash_password(
        "ExamplePassword",
        "sha256",
    )

    report = (
        AuditBuilder(
            target_hash=target_hash,
            algorithm="sha256",
        )
        .build()
    )

    writer = ReportWriter(tmp_path)

    json_path, text_path = writer.write_both(report)

    assert json_path.exists()
    assert text_path.exists()
    assert json_path.suffix == ".json"
    assert text_path.suffix == ".txt"


def test_custom_finding():
    """Custom findings should be supported."""
    target_hash = hash_password(
        "ExamplePassword",
        "sha256",
    )

    report = (
        AuditBuilder(
            target_hash=target_hash,
            algorithm="sha256",
        )
        .add_finding(
            category="Policy",
            severity="MEDIUM",
            title="Password policy review required",
            description=(
                "The laboratory assessment recommends reviewing "
                "the organization's password policy."
            ),
            recommendation=(
                "Require long unique passwords and prohibit "
                "known compromised passwords."
            ),
        )
        .build()
    )

    assert len(report.findings) == 1
    assert report.findings[0].severity == "MEDIUM"
    assert report.risk_level == "MEDIUM"