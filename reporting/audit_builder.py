"""
Audit report construction engine.

Combines results from password analysis, hash analysis, and controlled
offline attack simulations into a single structured assessment.
"""

from uuid import uuid4

from reporting.audit_models import (
    AuditFinding,
    AuditMetadata,
    AuditReport,
)


class AuditBuilder:
    """
    Build a unified credential-security audit.

    The builder accepts already-computed results from the analysis and
    attack modules. It does not perform authentication or credential
    collection.
    """

    def __init__(
        self,
        target_hash: str,
        algorithm: str | None = None,
    ):
        self.metadata = AuditMetadata.create(
            audit_id=f"AUD-{uuid4().hex[:12].upper()}"
        )

        self.target = {
            "hash": target_hash,
            "algorithm": algorithm,
            "type": "controlled_offline_test_target",
        }

        self.password_analysis = None
        self.hash_analysis = None
        self.attack_results: list[dict] = []
        self.findings: list[AuditFinding] = []
        self.recommendations: list[str] = []

    def add_password_analysis(self, analysis) -> "AuditBuilder":
        """Add password-strength analysis."""
        if hasattr(analysis, "to_dict"):
            self.password_analysis = analysis.to_dict()
        elif isinstance(analysis, dict):
            self.password_analysis = analysis
        else:
            raise TypeError(
                "Password analysis must be a dictionary or "
                "provide to_dict()."
            )

        self._derive_password_findings()
        return self

    def add_hash_analysis(self, analysis) -> "AuditBuilder":
        """Add hash-format/security analysis."""
        if hasattr(analysis, "to_dict"):
            self.hash_analysis = analysis.to_dict()
        elif isinstance(analysis, dict):
            self.hash_analysis = analysis
        else:
            raise TypeError(
                "Hash analysis must be a dictionary or "
                "provide to_dict()."
            )

        self._derive_hash_findings()
        return self

    def add_attack_result(self, result) -> "AuditBuilder":
        """Add an offline attack result."""
        if hasattr(result, "to_dict"):
            data = result.to_dict()
        elif isinstance(result, dict):
            data = result
        else:
            raise TypeError(
                "Attack result must be a dictionary or "
                "provide to_dict()."
            )

        self.attack_results.append(data)
        self._derive_attack_findings(data)

        return self

    def add_finding(
        self,
        category: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
    ) -> "AuditBuilder":
        """Add a custom finding."""
        finding = AuditFinding(
            category=category,
            severity=severity.upper(),
            title=title,
            description=description,
            recommendation=recommendation,
        )

        self.findings.append(finding)

        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)

        return self

    def _derive_password_findings(self) -> None:
        """Convert password-analysis weaknesses into audit findings."""
        if not self.password_analysis:
            return

        strength = self.password_analysis.get(
            "strength",
            "UNKNOWN",
        )

        score = self.password_analysis.get(
            "security_score",
            100,
        )

        findings = self.password_analysis.get(
            "findings",
            [],
        )

        if strength == "CRITICAL":
            severity = "CRITICAL"
        elif strength == "WEAK":
            severity = "HIGH"
        elif strength == "MODERATE":
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if strength in {
            "CRITICAL",
            "WEAK",
            "MODERATE",
        }:
            self.add_finding(
                category="Password Strength",
                severity=severity,
                title=f"Password strength classified as {strength}",
                description=(
                    f"The analyzed password received a security "
                    f"score of {score}."
                ),
                recommendation=(
                    "Use a long, unique password or passphrase "
                    "that does not contain predictable patterns."
                ),
            )

        for item in findings:
            if item not in self.recommendations:
                self.recommendations.append(item)

    def _derive_hash_findings(self) -> None:
        """Convert hash-analysis results into audit findings."""
        if not self.hash_analysis:
            return

        rating = self.hash_analysis.get(
            "security_rating",
            "UNKNOWN",
        )

        if rating in {"WEAK", "LEGACY"}:
            self.add_finding(
                category="Password Storage",
                severity="HIGH",
                title="Legacy or weak password hashing detected",
                description=(
                    f"The supplied hash format was classified as "
                    f"{rating} by the heuristic hash analyzer."
                ),
                recommendation=(
                    "Use an adaptive password-hashing algorithm such "
                    "as Argon2id, bcrypt, or another modern password "
                    "hashing scheme with appropriate work factors."
                ),
            )

        recommendations = self.hash_analysis.get(
            "recommendations",
            [],
        )

        for recommendation in recommendations:
            if recommendation not in self.recommendations:
                self.recommendations.append(recommendation)

    def _derive_attack_findings(self, result: dict) -> None:
        """Convert attack results into findings."""
        if result.get("match_found") is True:
            attack_type = result.get(
                "attack_type",
                "offline",
            )

            candidates = result.get(
                "candidates_tested",
                0,
            )

            self.add_finding(
                category="Credential Exposure",
                severity="HIGH",
                title="Password recovered during offline simulation",
                description=(
                    f"The controlled {attack_type} simulation "
                    f"recovered the supplied laboratory password "
                    f"after {candidates:,} candidate attempts."
                ),
                recommendation=(
                    "Use unique, high-entropy passwords and enforce "
                    "password policies that resist dictionary and "
                    "predictable-pattern attacks."
                ),
            )

        elif result.get("termination_reason") == "attempt_limit_reached":
            self.add_finding(
                category="Attack Simulation",
                severity="INFORMATIONAL",
                title="Attack simulation reached its safety limit",
                description=(
                    "The simulation stopped because its configured "
                    "candidate-attempt limit was reached."
                ),
                recommendation=(
                    "Review the controlled test scope and attempt "
                    "limit before conducting additional laboratory "
                    "testing."
                ),
            )

    def _calculate_risk(self) -> str:
        """Calculate the highest severity represented in findings."""
        severity_order = {
            "INFORMATIONAL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        if not self.findings:
            return "INFORMATIONAL"

        highest = max(
            self.findings,
            key=lambda finding: severity_order.get(
                finding.severity,
                0,
            ),
        )

        return highest.severity

    def build(self) -> AuditReport:
        """Construct the final audit report."""
        self.metadata.completed_at = (
            __import__("datetime")
            .datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
        )

        return AuditReport(
            metadata=self.metadata,
            target=self.target,
            password_analysis=self.password_analysis,
            hash_analysis=self.hash_analysis,
            attack_results=self.attack_results,
            findings=self.findings,
            recommendations=self.recommendations,
            risk_level=self._calculate_risk(),
        )