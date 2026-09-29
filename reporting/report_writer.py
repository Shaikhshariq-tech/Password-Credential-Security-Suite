"""
Report output utilities.

Supports JSON and human-readable text reports.
"""

import json
from pathlib import Path

from reporting.audit_models import AuditReport


class ReportWriter:
    """Write structured audit reports to disk."""

    def __init__(self, output_directory: str | Path):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    @staticmethod
    def _safe_filename(value: str) -> str:
        """Convert a report identifier into a safe filename."""
        allowed = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "-_"
        )

        return "".join(
            character
            for character in value
            if character in allowed
        )

    def write_json(
        self,
        report: AuditReport,
        filename: str | None = None,
    ) -> Path:
        """Write the audit report as formatted JSON."""
        if filename is None:
            audit_id = self._safe_filename(
                report.metadata.audit_id
            )
            filename = f"{audit_id}.json"

        path = self.output_directory / filename

        with path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report.to_dict(),
                file,
                indent=4,
                ensure_ascii=False,
            )

        return path

    def render_text(self, report: AuditReport) -> str:
        """Render a human-readable audit report."""
        lines: list[str] = []

        lines.append("=" * 72)
        lines.append(
            "PASSWORD & CREDENTIAL SECURITY AUDIT REPORT"
        )
        lines.append("=" * 72)

        lines.append("")
        lines.append("AUDIT INFORMATION")
        lines.append("-" * 72)
        lines.append(
            f"Audit ID       : {report.metadata.audit_id}"
        )
        lines.append(
            f"Started        : {report.metadata.started_at}"
        )
        lines.append(
            f"Completed      : {report.metadata.completed_at}"
        )
        lines.append(
            f"Scope          : {report.metadata.scope}"
        )
        lines.append(
            f"Authorized     : "
            f"{report.metadata.authorized_testing}"
        )

        lines.append("")
        lines.append("TARGET")
        lines.append("-" * 72)
        lines.append(
            f"Hash           : {report.target.get('hash')}"
        )
        lines.append(
            f"Algorithm      : "
            f"{report.target.get('algorithm')}"
        )
        lines.append(
            f"Target Type    : "
            f"{report.target.get('type')}"
        )

        lines.append("")
        lines.append("OVERALL RISK")
        lines.append("-" * 72)
        lines.append(
            f"Risk Level     : {report.risk_level}"
        )

        if report.password_analysis:
            lines.append("")
            lines.append("PASSWORD ANALYSIS")
            lines.append("-" * 72)

            for key in (
                "strength",
                "security_score",
                "entropy_bits",
                "predictability_score",
            ):
                if key in report.password_analysis:
                    label = key.replace("_", " ").title()
                    lines.append(
                        f"{label:<22}: "
                        f"{report.password_analysis[key]}"
                    )

        if report.hash_analysis:
            lines.append("")
            lines.append("HASH ANALYSIS")
            lines.append("-" * 72)

            for key in (
                "algorithm",
                "confidence",
                "security_rating",
                "salted_format",
            ):
                if key in report.hash_analysis:
                    label = key.replace("_", " ").title()
                    lines.append(
                        f"{label:<22}: "
                        f"{report.hash_analysis[key]}"
                    )

        if report.attack_results:
            lines.append("")
            lines.append("ATTACK SIMULATION RESULTS")
            lines.append("-" * 72)

            for index, result in enumerate(
                report.attack_results,
                start=1,
            ):
                lines.append(
                    f"Simulation #{index}"
                )
                lines.append(
                    f"  Type             : "
                    f"{result.get('attack_type')}"
                )
                lines.append(
                    f"  Algorithm        : "
                    f"{result.get('algorithm')}"
                )
                lines.append(
                    f"  Candidates       : "
                    f"{result.get('candidates_tested'):,}"
                )
                lines.append(
                    f"  Match Found      : "
                    f"{result.get('match_found')}"
                )
                lines.append(
                    f"  Status           : "
                    f"{result.get('status')}"
                )
                lines.append(
                    f"  Termination      : "
                    f"{result.get('termination_reason')}"
                )
                lines.append(
                    f"  Attempts/sec     : "
                    f"{result.get('candidates_per_second', 0):,.2f}"
                )

                if result.get("matched_password"):
                    lines.append(
                        "  Laboratory Match : "
                        f"{result.get('matched_password')}"
                    )

        if report.findings:
            lines.append("")
            lines.append("SECURITY FINDINGS")
            lines.append("-" * 72)

            for index, finding in enumerate(
                report.findings,
                start=1,
            ):
                lines.append(
                    f"{index}. [{finding.severity}] "
                    f"{finding.title}"
                )
                lines.append(
                    f"   Category      : "
                    f"{finding.category}"
                )
                lines.append(
                    f"   Description   : "
                    f"{finding.description}"
                )
                lines.append(
                    f"   Recommendation: "
                    f"{finding.recommendation}"
                )

        if report.recommendations:
            lines.append("")
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 72)

            for index, recommendation in enumerate(
                report.recommendations,
                start=1,
            ):
                lines.append(
                    f"{index}. {recommendation}"
                )

        lines.append("")
        lines.append("=" * 72)
        lines.append(
            "END OF CONTROLLED SECURITY AUDIT"
        )
        lines.append("=" * 72)

        return "\n".join(lines)

    def write_text(
        self,
        report: AuditReport,
        filename: str | None = None,
    ) -> Path:
        """Write a human-readable text report."""
        if filename is None:
            audit_id = self._safe_filename(
                report.metadata.audit_id
            )
            filename = f"{audit_id}.txt"

        path = self.output_directory / filename

        path.write_text(
            self.render_text(report),
            encoding="utf-8",
        )

        return path

    def write_both(
        self,
        report: AuditReport,
    ) -> tuple[Path, Path]:
        """Write both JSON and text versions."""
        return (
            self.write_json(report),
            self.write_text(report),
        )