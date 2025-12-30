"""Tests for analyzer modules."""

import pytest
from unittest.mock import MagicMock

from src.analyzers.base_analyzer import Severity, Finding, AnalysisResult, BaseAnalyzer
from src.analyzers.traffic_analyzer import TrafficAnalyzer
from src.analyzers.anomaly_detector import AnomalyDetector
from src.analyzers.attack_detector import AttackDetector
from src.pcap_parser import ParsedPCAP, Packet, Connection


def create_test_pcap(
    packets: list[Packet] = None,
    connections: dict = None,
) -> ParsedPCAP:
    """Create a test ParsedPCAP object."""
    if packets is None:
        packets = []
    if connections is None:
        connections = {}

    return ParsedPCAP(
        file_path="/test/capture.pcap",
        packet_count=len(packets),
        start_time=min((p.timestamp for p in packets), default=0.0),
        end_time=max((p.timestamp for p in packets), default=0.0),
        packets=packets,
        connections=connections,
        dns_queries=[],
        http_requests=[],
        unique_ips=set(p.src_ip for p in packets if p.src_ip) | set(p.dst_ip for p in packets if p.dst_ip),
        unique_ports=set(p.dst_port for p in packets if p.dst_port),
        protocol_counts={},
    )


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_scores(self):
        """Test severity score values."""
        assert Severity.LOW.score == 3
        assert Severity.MEDIUM.score == 5
        assert Severity.HIGH.score == 8
        assert Severity.CRITICAL.score == 10

    def test_from_score(self):
        """Test severity from score."""
        assert Severity.from_score(1) == Severity.LOW
        assert Severity.from_score(5) == Severity.MEDIUM
        assert Severity.from_score(8) == Severity.HIGH
        assert Severity.from_score(10) == Severity.CRITICAL


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category="Test",
            source_ip="192.168.1.1",
        )

        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.source_ip == "192.168.1.1"

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.CRITICAL,
            category="Test",
            mitre_technique="T1046",
        )

        data = finding.to_dict()
        assert data["title"] == "Test Finding"
        assert data["severity"] == "CRITICAL"
        assert data["severity_score"] == 10
        assert data["mitre_technique"] == "T1046"


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_finding_counts(self):
        """Test finding count properties."""
        findings = [
            Finding("F1", "D1", Severity.CRITICAL, "Test"),
            Finding("F2", "D2", Severity.CRITICAL, "Test"),
            Finding("F3", "D3", Severity.HIGH, "Test"),
            Finding("F4", "D4", Severity.MEDIUM, "Test"),
        ]

        result = AnalysisResult(
            analyzer_name="TestAnalyzer",
            findings=findings,
        )

        assert result.finding_count == 4
        assert result.critical_count == 2
        assert result.high_count == 1

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        findings = [
            Finding("F1", "D1", Severity.CRITICAL, "Test"),
            Finding("F2", "D2", Severity.HIGH, "Test"),
            Finding("F3", "D3", Severity.HIGH, "Test"),
        ]

        result = AnalysisResult(
            analyzer_name="TestAnalyzer",
            findings=findings,
        )

        high_findings = result.get_findings_by_severity(Severity.HIGH)
        assert len(high_findings) == 2


class TestTrafficAnalyzer:
    """Tests for TrafficAnalyzer."""

    def test_analyze_empty_pcap(self):
        """Test analyzing empty PCAP."""
        analyzer = TrafficAnalyzer()
        pcap = create_test_pcap()

        result = analyzer.analyze(pcap)

        assert result.analyzer_name == "TrafficAnalyzer"
        assert result.finding_count == 0

    def test_detect_suspicious_port(self):
        """Test detection of suspicious port usage."""
        packets = [
            Packet(
                timestamp=1000.0 + i,
                src_ip="192.168.1.1",
                dst_ip="10.0.0.1",
                src_port=12345,
                dst_port=4444,  # Metasploit default
                protocol="TCP",
                length=100,
            )
            for i in range(10)
        ]

        analyzer = TrafficAnalyzer()
        pcap = create_test_pcap(packets)
        # Set protocol counts
        pcap.protocol_counts = {"TCP": 10}

        result = analyzer.analyze(pcap)

        # Should detect suspicious port
        port_findings = [
            f for f in result.findings if "4444" in f.title or "Suspicious Port" in f.title
        ]
        assert len(port_findings) > 0


class TestAnomalyDetector:
    """Tests for AnomalyDetector."""

    def test_analyze_empty_pcap(self):
        """Test analyzing empty PCAP."""
        analyzer = AnomalyDetector()
        pcap = create_test_pcap()

        result = analyzer.analyze(pcap)

        assert result.analyzer_name == "AnomalyDetector"

    def test_detect_beaconing(self):
        """Test C2 beaconing detection."""
        # Create packets with regular intervals (beaconing pattern)
        packets = []
        for i in range(20):
            packets.append(
                Packet(
                    timestamp=1000.0 + (i * 60.0),  # Every 60 seconds
                    src_ip="192.168.1.100",
                    dst_ip="10.20.30.40",
                    src_port=54321,
                    dst_port=443,
                    protocol="TCP",
                    length=100,
                )
            )

        config = {"detection": {"beacon_interval_tolerance": 0.1, "min_beacon_count": 10}}
        analyzer = AnomalyDetector(config)
        pcap = create_test_pcap(packets)

        result = analyzer.analyze(pcap)

        # Should detect beaconing
        beacon_findings = [f for f in result.findings if "Beacon" in f.title]
        assert len(beacon_findings) > 0


class TestAttackDetector:
    """Tests for AttackDetector."""

    def test_analyze_empty_pcap(self):
        """Test analyzing empty PCAP."""
        analyzer = AttackDetector()
        pcap = create_test_pcap()

        result = analyzer.analyze(pcap)

        assert result.analyzer_name == "AttackDetector"

    def test_detect_port_scan(self):
        """Test port scan detection."""
        # Create packets accessing many different ports
        packets = []
        for port in range(1, 50):
            packets.append(
                Packet(
                    timestamp=1000.0 + port,
                    src_ip="192.168.1.100",
                    dst_ip="192.168.1.1",
                    src_port=54321,
                    dst_port=port,
                    protocol="TCP",
                    length=64,
                )
            )

        config = {"detection": {"port_scan_threshold": 20, "port_scan_window": 60}}
        analyzer = AttackDetector(config)
        pcap = create_test_pcap(packets)

        result = analyzer.analyze(pcap)

        # Should detect port scan
        scan_findings = [f for f in result.findings if "Port Scan" in f.title]
        assert len(scan_findings) > 0

    def test_classify_scan_type(self):
        """Test port scan classification."""
        analyzer = AttackDetector()

        # Sequential scan
        sequential_ports = set(range(1, 100))
        scan_type = analyzer._classify_scan_type(sequential_ports)
        assert "Sequential" in scan_type or "Full" in scan_type

        # Common ports scan
        common_ports = {22, 80, 443, 21, 25, 3389}
        scan_type = analyzer._classify_scan_type(common_ports)
        assert "Common" in scan_type


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
