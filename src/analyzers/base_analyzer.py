"""Base analyzer class and common types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from ..pcap_parser import ParsedPCAP


class Severity(Enum):
    """Finding severity levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def score(self) -> int:
        """Get numeric score for severity."""
        scores = {
            Severity.LOW: 3,
            Severity.MEDIUM: 5,
            Severity.HIGH: 8,
            Severity.CRITICAL: 10,
        }
        return scores[self]

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        """Get severity from numeric score."""
        if score >= 9:
            return cls.CRITICAL
        elif score >= 7:
            return cls.HIGH
        elif score >= 4:
            return cls.MEDIUM
        else:
            return cls.LOW


@dataclass
class Finding:
    """Represents a security finding."""

    title: str
    description: str
    severity: Severity
    category: str
    timestamp: Optional[float] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    raw_data: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "severity_score": self.severity.score,
            "category": self.category,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
        }


@dataclass
class AnalysisResult:
    """Container for analysis results."""

    analyzer_name: str
    findings: list[Finding]
    statistics: dict[str, Any] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "analyzer_name": self.analyzer_name,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "statistics": self.statistics,
            "iocs": self.iocs,
        }


class BaseAnalyzer(ABC):
    """Abstract base class for network analyzers."""

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """
        Initialize analyzer.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.name = self.__class__.__name__

    @abstractmethod
    def analyze(self, pcap_data: ParsedPCAP) -> AnalysisResult:
        """
        Analyze parsed PCAP data.

        Args:
            pcap_data: Parsed PCAP data

        Returns:
            AnalysisResult containing findings
        """
        pass

    def _create_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        category: str,
        **kwargs: Any,
    ) -> Finding:
        """Helper method to create findings."""
        return Finding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            **kwargs,
        )
