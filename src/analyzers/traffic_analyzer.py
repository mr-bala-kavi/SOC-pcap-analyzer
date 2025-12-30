"""Traffic analysis and statistics module."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Optional

from ..pcap_parser import ParsedPCAP
from ..utils.helpers import format_bytes
from .base_analyzer import AnalysisResult, BaseAnalyzer, Finding, Severity


@dataclass
class TrafficStatistics:
    """Container for traffic statistics."""

    total_packets: int
    total_bytes: int
    duration_seconds: float
    unique_ips: int
    unique_ports: int
    top_talkers: list[tuple[str, int]]
    top_destinations: list[tuple[str, int]]
    protocol_distribution: dict[str, int]
    port_distribution: dict[int, int]
    packets_per_second: float
    bytes_per_second: float


class TrafficAnalyzer(BaseAnalyzer):
    """Analyze traffic patterns and generate statistics."""

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize traffic analyzer."""
        super().__init__(config)
        self.name = "TrafficAnalyzer"

    def analyze(self, pcap_data: ParsedPCAP) -> AnalysisResult:
        """
        Analyze traffic patterns and statistics.

        Args:
            pcap_data: Parsed PCAP data

        Returns:
            AnalysisResult with traffic statistics and findings
        """
        findings: list[Finding] = []
        iocs: dict[str, list[str]] = {"ips": [], "ports": [], "domains": []}

        # Calculate statistics
        stats = self._calculate_statistics(pcap_data)

        # Analyze for suspicious patterns
        findings.extend(self._analyze_traffic_volume(pcap_data, stats))
        findings.extend(self._analyze_protocol_anomalies(pcap_data, stats))
        findings.extend(self._analyze_port_usage(pcap_data, stats))
        findings.extend(self._analyze_dns_traffic(pcap_data))
        findings.extend(self._analyze_http_traffic(pcap_data))

        # Collect IOCs
        for finding in findings:
            if finding.source_ip and finding.source_ip not in iocs["ips"]:
                iocs["ips"].append(finding.source_ip)
            if finding.destination_ip and finding.destination_ip not in iocs["ips"]:
                iocs["ips"].append(finding.destination_ip)

        # Extract domains from DNS
        for dns in pcap_data.dns_queries:
            if dns.query_name not in iocs["domains"]:
                iocs["domains"].append(dns.query_name)

        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            statistics=self._stats_to_dict(stats),
            iocs=iocs,
        )

    def _calculate_statistics(self, pcap_data: ParsedPCAP) -> TrafficStatistics:
        """Calculate traffic statistics from parsed PCAP."""
        # Count source IPs
        src_counter: Counter[str] = Counter()
        dst_counter: Counter[str] = Counter()
        port_counter: Counter[int] = Counter()
        total_bytes = 0

        for packet in pcap_data.packets:
            if packet.src_ip:
                src_counter[packet.src_ip] += 1
            if packet.dst_ip:
                dst_counter[packet.dst_ip] += 1
            if packet.dst_port:
                port_counter[packet.dst_port] += 1
            total_bytes += packet.length

        duration = pcap_data.duration
        pps = pcap_data.packet_count / duration if duration > 0 else 0
        bps = total_bytes / duration if duration > 0 else 0

        return TrafficStatistics(
            total_packets=pcap_data.packet_count,
            total_bytes=total_bytes,
            duration_seconds=duration,
            unique_ips=len(pcap_data.unique_ips),
            unique_ports=len(pcap_data.unique_ports),
            top_talkers=src_counter.most_common(10),
            top_destinations=dst_counter.most_common(10),
            protocol_distribution=dict(pcap_data.protocol_counts),
            port_distribution=dict(port_counter.most_common(20)),
            packets_per_second=pps,
            bytes_per_second=bps,
        )

    def _analyze_traffic_volume(
        self, pcap_data: ParsedPCAP, stats: TrafficStatistics
    ) -> list[Finding]:
        """Analyze traffic volume for anomalies."""
        findings: list[Finding] = []

        # High traffic volume per host
        for ip, count in stats.top_talkers[:5]:
            packet_ratio = count / stats.total_packets if stats.total_packets > 0 else 0
            if packet_ratio > 0.5:  # Single IP responsible for >50% traffic
                findings.append(
                    self._create_finding(
                        title=f"High Traffic Volume from {ip}",
                        description=(
                            f"IP {ip} generated {count} packets ({packet_ratio*100:.1f}% "
                            f"of total traffic). This could indicate data exfiltration, "
                            f"DDoS activity, or a compromised host."
                        ),
                        severity=Severity.MEDIUM,
                        category="Traffic Anomaly",
                        source_ip=ip,
                        evidence=[
                            f"Packet count: {count}",
                            f"Traffic ratio: {packet_ratio*100:.1f}%",
                        ],
                        recommendations=[
                            "Investigate the source IP for signs of compromise",
                            "Review firewall logs for this IP",
                            "Check if this traffic pattern is expected",
                        ],
                    )
                )

        return findings

    def _analyze_protocol_anomalies(
        self, pcap_data: ParsedPCAP, stats: TrafficStatistics
    ) -> list[Finding]:
        """Analyze protocol distribution for anomalies."""
        findings: list[Finding] = []

        # Check for unusual protocols
        suspicious_protocols = ["IRC", "TELNET", "FTP", "TFTP"]
        for proto in suspicious_protocols:
            if proto in stats.protocol_distribution:
                count = stats.protocol_distribution[proto]
                findings.append(
                    self._create_finding(
                        title=f"Suspicious Protocol Detected: {proto}",
                        description=(
                            f"Detected {count} packets using {proto} protocol. "
                            f"This protocol is often associated with legacy systems "
                            f"or malicious activity."
                        ),
                        severity=Severity.MEDIUM,
                        category="Protocol Anomaly",
                        protocol=proto,
                        evidence=[f"Packet count: {count}"],
                        recommendations=[
                            f"Verify if {proto} traffic is authorized",
                            "Consider using encrypted alternatives",
                            "Monitor for data exfiltration",
                        ],
                        mitre_technique="T1071",
                        mitre_tactic="Command and Control",
                    )
                )

        return findings

    def _analyze_port_usage(
        self, pcap_data: ParsedPCAP, stats: TrafficStatistics
    ) -> list[Finding]:
        """Analyze port usage patterns."""
        findings: list[Finding] = []

        # Known suspicious ports
        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Android ADB",
            6666: "IRC (often malware)",
            6667: "IRC",
            31337: "Back Orifice",
            12345: "NetBus",
            1337: "Common hacker port",
            8080: "HTTP Proxy (review if unexpected)",
        }

        for port, description in suspicious_ports.items():
            if port in stats.port_distribution:
                count = stats.port_distribution[port]
                findings.append(
                    self._create_finding(
                        title=f"Suspicious Port Activity: {port}",
                        description=(
                            f"Detected {count} packets to port {port} ({description}). "
                            f"This port is commonly associated with malicious tools."
                        ),
                        severity=Severity.HIGH,
                        category="Suspicious Port",
                        destination_port=port,
                        evidence=[
                            f"Port: {port}",
                            f"Description: {description}",
                            f"Packet count: {count}",
                        ],
                        recommendations=[
                            f"Block port {port} at the firewall if not needed",
                            "Investigate hosts communicating on this port",
                            "Search for malware associated with this port",
                        ],
                        mitre_technique="T1571",
                        mitre_tactic="Command and Control",
                    )
                )

        return findings

    def _analyze_dns_traffic(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Analyze DNS traffic for anomalies."""
        findings: list[Finding] = []

        # Track DNS query patterns
        domain_counter: Counter[str] = Counter()
        long_queries: list[str] = []

        for dns in pcap_data.dns_queries:
            domain_counter[dns.query_name] += 1
            if len(dns.query_name) > 50:
                long_queries.append(dns.query_name)

        # Excessive queries to single domain
        for domain, count in domain_counter.most_common(5):
            if count > 100:
                findings.append(
                    self._create_finding(
                        title=f"Excessive DNS Queries: {domain}",
                        description=(
                            f"Detected {count} DNS queries for {domain}. "
                            f"This could indicate DNS tunneling, C2 communication, "
                            f"or a misconfigured application."
                        ),
                        severity=Severity.MEDIUM,
                        category="DNS Anomaly",
                        evidence=[f"Query count: {count}", f"Domain: {domain}"],
                        recommendations=[
                            "Investigate the querying host",
                            "Check if domain is known malicious",
                            "Review DNS logs for patterns",
                        ],
                        mitre_technique="T1071.004",
                        mitre_tactic="Command and Control",
                    )
                )

        # Long DNS queries (potential tunneling)
        if long_queries:
            findings.append(
                self._create_finding(
                    title="Potential DNS Tunneling Detected",
                    description=(
                        f"Detected {len(long_queries)} DNS queries with unusually "
                        f"long subdomain names. This is a common indicator of DNS "
                        f"tunneling used for data exfiltration or C2."
                    ),
                    severity=Severity.HIGH,
                    category="DNS Tunneling",
                    evidence=[f"Sample query: {long_queries[0][:80]}..."]
                    if long_queries
                    else [],
                    recommendations=[
                        "Block suspicious domains at DNS level",
                        "Implement DNS query length limits",
                        "Use DNS security solutions",
                    ],
                    mitre_technique="T1048.003",
                    mitre_tactic="Exfiltration",
                )
            )

        return findings

    def _analyze_http_traffic(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Analyze HTTP traffic for anomalies."""
        findings: list[Finding] = []

        # Track user agents
        ua_counter: Counter[str] = Counter()
        suspicious_uas: list[str] = []

        suspicious_ua_patterns = [
            "curl",
            "wget",
            "python",
            "powershell",
            "certutil",
            "nc",
            "nmap",
        ]

        for http in pcap_data.http_requests:
            if http.user_agent:
                ua_counter[http.user_agent] += 1
                ua_lower = http.user_agent.lower()
                for pattern in suspicious_ua_patterns:
                    if pattern in ua_lower:
                        suspicious_uas.append(http.user_agent)
                        break

        # Flag suspicious user agents
        if suspicious_uas:
            findings.append(
                self._create_finding(
                    title="Suspicious HTTP User-Agents Detected",
                    description=(
                        f"Detected {len(suspicious_uas)} HTTP requests with "
                        f"suspicious user-agent strings commonly associated with "
                        f"automated tools or malware."
                    ),
                    severity=Severity.MEDIUM,
                    category="HTTP Anomaly",
                    evidence=[f"User-Agent: {ua}" for ua in set(suspicious_uas)[:5]],
                    recommendations=[
                        "Investigate the source hosts",
                        "Block known malicious user-agents",
                        "Review downloaded content",
                    ],
                    mitre_technique="T1071.001",
                    mitre_tactic="Command and Control",
                )
            )

        return findings

    def _stats_to_dict(self, stats: TrafficStatistics) -> dict[str, Any]:
        """Convert TrafficStatistics to dictionary."""
        return {
            "total_packets": stats.total_packets,
            "total_bytes": stats.total_bytes,
            "total_bytes_formatted": format_bytes(stats.total_bytes),
            "duration_seconds": round(stats.duration_seconds, 2),
            "unique_ips": stats.unique_ips,
            "unique_ports": stats.unique_ports,
            "top_talkers": [{"ip": ip, "packets": count} for ip, count in stats.top_talkers],
            "top_destinations": [
                {"ip": ip, "packets": count} for ip, count in stats.top_destinations
            ],
            "protocol_distribution": stats.protocol_distribution,
            "port_distribution": {str(k): v for k, v in stats.port_distribution.items()},
            "packets_per_second": round(stats.packets_per_second, 2),
            "bytes_per_second": round(stats.bytes_per_second, 2),
        }
