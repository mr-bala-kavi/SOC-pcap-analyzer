"""Security incident report generator."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..analyzers.base_analyzer import AnalysisResult, Finding, Severity
from ..pcap_parser import ParsedPCAP
from ..threat_intel.mitre_mapper import MitreMapper
from ..utils.helpers import format_bytes, format_timestamp
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ReportData:
    """Container for all report data."""

    # Metadata
    report_id: str
    generated_at: str
    pcap_file: str
    analysis_duration: float

    # Summary
    total_packets: int
    total_bytes: int
    capture_duration: float
    unique_ips: int
    unique_ports: int

    # Findings
    findings: list[Finding]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    # IOCs
    malicious_ips: list[str]
    malicious_domains: list[str]
    suspicious_ports: list[int]

    # Statistics
    top_talkers: list[dict[str, Any]]
    protocol_distribution: dict[str, int]

    # MITRE ATT&CK
    mitre_coverage: dict[str, list[dict[str, Any]]]

    # Timeline
    timeline: list[dict[str, Any]]

    # Recommendations
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for template rendering."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "pcap_file": self.pcap_file,
            "analysis_duration": self.analysis_duration,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_bytes_formatted": format_bytes(self.total_bytes),
            "capture_duration": self.capture_duration,
            "unique_ips": self.unique_ips,
            "unique_ports": self.unique_ports,
            "findings": [f.to_dict() for f in self.findings],
            "findings_by_severity": {
                "critical": [f.to_dict() for f in self.findings if f.severity == Severity.CRITICAL],
                "high": [f.to_dict() for f in self.findings if f.severity == Severity.HIGH],
                "medium": [f.to_dict() for f in self.findings if f.severity == Severity.MEDIUM],
                "low": [f.to_dict() for f in self.findings if f.severity == Severity.LOW],
            },
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "total_findings": len(self.findings),
            "malicious_ips": self.malicious_ips,
            "malicious_domains": self.malicious_domains,
            "suspicious_ports": self.suspicious_ports,
            "top_talkers": self.top_talkers,
            "protocol_distribution": self.protocol_distribution,
            "mitre_coverage": self.mitre_coverage,
            "timeline": self.timeline,
            "recommendations": self.recommendations,
            "risk_score": self._calculate_risk_score(),
            "risk_level": self._get_risk_level(),
        }

    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        score = 0
        score += self.critical_count * 25
        score += self.high_count * 15
        score += self.medium_count * 5
        score += self.low_count * 1
        return min(score, 100)

    def _get_risk_level(self) -> str:
        """Get risk level based on findings."""
        if self.critical_count > 0:
            return "CRITICAL"
        elif self.high_count > 0:
            return "HIGH"
        elif self.medium_count > 0:
            return "MEDIUM"
        elif self.low_count > 0:
            return "LOW"
        return "NONE"


class ReportGenerator:
    """Generate security incident reports from analysis results."""

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """
        Initialize report generator.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.report_config = self.config.get("reporting", {})
        self.title_prefix = self.report_config.get("title_prefix", "Security Incident Report")
        self.mitre_mapper = MitreMapper()

    def generate(
        self,
        pcap_data: ParsedPCAP,
        analysis_results: list[AnalysisResult],
        analysis_duration: float = 0.0,
    ) -> ReportData:
        """
        Generate a comprehensive security report.

        Args:
            pcap_data: Parsed PCAP data
            analysis_results: Results from all analyzers
            analysis_duration: Time taken for analysis

        Returns:
            ReportData containing all report information
        """
        logger.info("Generating security report...")

        # Collect all findings
        all_findings: list[Finding] = []
        all_iocs: dict[str, list[str]] = {"ips": [], "domains": [], "ports": []}
        all_stats: dict[str, Any] = {}

        for result in analysis_results:
            all_findings.extend(result.findings)
            for ioc_type, values in result.iocs.items():
                if ioc_type in all_iocs:
                    all_iocs[ioc_type].extend(values)
            all_stats.update(result.statistics)

        # Deduplicate IOCs
        malicious_ips = list(set(all_iocs.get("ips", [])))
        malicious_domains = list(set(all_iocs.get("domains", [])))
        suspicious_ports = [int(p) for p in set(all_iocs.get("ports", []))]

        # Sort findings by severity
        all_findings.sort(key=lambda f: f.severity.score, reverse=True)

        # Count by severity
        critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)

        # Build MITRE coverage
        mitre_coverage = self._build_mitre_coverage(all_findings)

        # Build timeline
        timeline = self._build_timeline(all_findings, pcap_data)

        # Generate recommendations
        recommendations = self._generate_recommendations(all_findings)

        # Build top talkers
        top_talkers = all_stats.get("top_talkers", [])

        report_data = ReportData(
            report_id=self._generate_report_id(),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            pcap_file=pcap_data.file_path,
            analysis_duration=round(analysis_duration, 2),
            total_packets=pcap_data.packet_count,
            total_bytes=sum(p.length for p in pcap_data.packets),
            capture_duration=round(pcap_data.duration, 2),
            unique_ips=len(pcap_data.unique_ips),
            unique_ports=len(pcap_data.unique_ports),
            findings=all_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            malicious_ips=malicious_ips[:50],  # Limit IOCs
            malicious_domains=malicious_domains[:50],
            suspicious_ports=suspicious_ports[:20],
            top_talkers=top_talkers,
            protocol_distribution=all_stats.get("protocol_distribution", {}),
            mitre_coverage=mitre_coverage,
            timeline=timeline,
            recommendations=recommendations,
        )

        logger.info(
            f"Report generated: {len(all_findings)} findings "
            f"({critical_count} critical, {high_count} high)"
        )

        return report_data

    def _generate_report_id(self) -> str:
        """Generate unique report ID."""
        import hashlib
        import time

        timestamp = str(time.time()).encode()
        return hashlib.sha256(timestamp).hexdigest()[:12].upper()

    def _build_mitre_coverage(
        self, findings: list[Finding]
    ) -> dict[str, list[dict[str, Any]]]:
        """Build MITRE ATT&CK coverage summary."""
        coverage = self.mitre_mapper.get_coverage_summary(findings)

        result: dict[str, list[dict[str, Any]]] = {}
        for tactic, techniques in coverage.items():
            result[tactic] = [t.to_dict() for t in techniques]

        return result

    def _build_timeline(
        self, findings: list[Finding], pcap_data: ParsedPCAP
    ) -> list[dict[str, Any]]:
        """Build chronological timeline of events."""
        events: list[dict[str, Any]] = []

        # Add findings with timestamps
        for finding in findings:
            if finding.timestamp:
                events.append({
                    "timestamp": finding.timestamp,
                    "time_formatted": format_timestamp(finding.timestamp),
                    "type": "finding",
                    "severity": finding.severity.name,
                    "title": finding.title,
                    "source_ip": finding.source_ip,
                    "destination_ip": finding.destination_ip,
                })

        # Add capture start/end
        if pcap_data.start_time > 0:
            events.append({
                "timestamp": pcap_data.start_time,
                "time_formatted": format_timestamp(pcap_data.start_time),
                "type": "capture_start",
                "severity": "INFO",
                "title": "Capture Started",
            })

        if pcap_data.end_time > 0:
            events.append({
                "timestamp": pcap_data.end_time,
                "time_formatted": format_timestamp(pcap_data.end_time),
                "type": "capture_end",
                "severity": "INFO",
                "title": "Capture Ended",
            })

        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", 0))

        return events

    def _generate_recommendations(self, findings: list[Finding]) -> list[str]:
        """Generate prioritized recommendations based on findings."""
        recommendations: list[str] = []
        seen: set[str] = set()

        # Prioritize by severity
        for finding in sorted(findings, key=lambda f: f.severity.score, reverse=True):
            for rec in finding.recommendations:
                if rec not in seen:
                    recommendations.append(rec)
                    seen.add(rec)

        # Add general recommendations if critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            general_recs = [
                "Initiate incident response procedures immediately",
                "Preserve evidence and maintain chain of custody",
                "Consider engaging external incident response team",
                "Notify relevant stakeholders and management",
            ]
            for rec in general_recs:
                if rec not in seen:
                    recommendations.insert(0, rec)
                    seen.add(rec)

        return recommendations[:20]  # Limit recommendations


def create_executive_summary(report_data: ReportData) -> str:
    """
    Create executive summary text from report data.

    Args:
        report_data: Report data

    Returns:
        Executive summary string
    """
    summary_parts = []

    # Risk assessment
    summary_parts.append(
        f"Overall Risk Level: {report_data._get_risk_level()} "
        f"(Score: {report_data._calculate_risk_score()}/100)"
    )

    # Key statistics
    summary_parts.append(
        f"\nAnalysis of {report_data.pcap_file} identified "
        f"{len(report_data.findings)} security findings across "
        f"{report_data.total_packets:,} packets."
    )

    # Severity breakdown
    if report_data.critical_count > 0:
        summary_parts.append(
            f"\n{report_data.critical_count} CRITICAL finding(s) require immediate attention."
        )

    if report_data.high_count > 0:
        summary_parts.append(
            f"{report_data.high_count} HIGH severity finding(s) should be addressed promptly."
        )

    # Top threats
    critical_findings = [f for f in report_data.findings if f.severity == Severity.CRITICAL]
    if critical_findings:
        summary_parts.append("\nKey Threats Identified:")
        for finding in critical_findings[:3]:
            summary_parts.append(f"  - {finding.title}")

    # IOC summary
    if report_data.malicious_ips:
        summary_parts.append(f"\n{len(report_data.malicious_ips)} suspicious IP(s) identified")

    if report_data.malicious_domains:
        summary_parts.append(f"{len(report_data.malicious_domains)} suspicious domain(s) identified")

    return "\n".join(summary_parts)
