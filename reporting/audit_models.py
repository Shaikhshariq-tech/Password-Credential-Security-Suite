"""
Data models for the Password & Credential Security Audit Suite.

These models provide a consistent structure for combining password
intelligence, hash analysis, and controlled offline attack results.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditFinding:
    """Represents an individual security finding."""

    category: str
    severity: str
    title: str
    description: str
    recommendation: str

    def to_dict(self) -> dict:
        """Serialize the finding."""
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditMetadata:
    """Metadata describing an audit execution."""

    audit_id: str
    started_at: str
    completed_at: str
    scope: str = "Controlled laboratory credential-security assessment"
    authorized_testing: bool = True

    @classmethod
    def create(cls, audit_id: str) -> "AuditMetadata":
        """Create metadata with the current UTC timestamp."""
        timestamp = datetime.now(timezone.utc).isoformat()

        return cls(
            audit_id=audit_id,
            started_at=timestamp,
            completed_at=timestamp,
        )

    def to_dict(self) -> dict:
        """Serialize metadata."""
        return {
            "audit_id": self.audit_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "scope": self.scope,
            "authorized_testing": self.authorized_testing,
        }


@dataclass
class AuditReport:
    """Complete structured security audit report."""

    metadata: AuditMetadata
    target: dict
    password_analysis: dict | None = None
    hash_analysis: dict | None = None
    attack_results: list[dict] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_level: str = "INFORMATIONAL"

    def to_dict(self) -> dict:
        """Serialize the complete report."""
        return {
            "metadata": self.metadata.to_dict(),
            "target": self.target,
            "password_analysis": self.password_analysis,
            "hash_analysis": self.hash_analysis,
            "attack_results": self.attack_results,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "recommendations": self.recommendations,
            "risk_level": self.risk_level,
        }