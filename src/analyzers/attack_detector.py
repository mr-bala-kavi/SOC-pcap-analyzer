"""Attack signature detection module."""

from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import yaml

from ..pcap_parser import ParsedPCAP
from .base_analyzer import AnalysisResult, BaseAnalyzer, Finding, Severity


class AttackDetector(BaseAnalyzer):
    """Detect known attack patterns and signatures."""

    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
        rules_path: Optional[str] = None,
    ):
        """
        Initialize attack detector.

        Args:
            config: Configuration dictionary
            rules_path: Path to attack signatures YAML file
        """
        super().__init__(config)
        self.name = "AttackDetector"

        # Load thresholds from config
        detection_config = self.config.get("detection", {})
        self.port_scan_threshold = detection_config.get("port_scan_threshold", 20)
        self.port_scan_window = detection_config.get("port_scan_window", 60)
        self.brute_force_threshold = detection_config.get("brute_force_threshold", 5)
        self.brute_force_window = detection_config.get("brute_force_window", 300)

        # Load custom rules
        self.rules = self._load_rules(rules_path) if rules_path else {}

    def _load_rules(self, rules_path: str) -> dict[str, Any]:
        """Load attack signature rules from YAML file."""
        path = Path(rules_path)
        if not path.exists():
            return {}

        with open(path, "r") as f:
            return yaml.safe_load(f) or {}

    def analyze(self, pcap_data: ParsedPCAP) -> AnalysisResult:
        """
        Detect attack patterns in traffic.

        Args:
            pcap_data: Parsed PCAP data

        Returns:
            AnalysisResult with attack findings
        """
        findings: list[Finding] = []
        iocs: dict[str, list[str]] = {"ips": [], "ports": []}

        # Run attack detections
        findings.extend(self._detect_port_scan(pcap_data))
        findings.extend(self._detect_brute_force(pcap_data))
        findings.extend(self._detect_sql_injection(pcap_data))
        findings.extend(self._detect_directory_traversal(pcap_data))
        findings.extend(self._detect_command_injection(pcap_data))
        findings.extend(self._detect_dos_patterns(pcap_data))

        # Collect IOCs
        for finding in findings:
            if finding.source_ip and finding.source_ip not in iocs["ips"]:
                iocs["ips"].append(finding.source_ip)
            if finding.destination_port:
                port_str = str(finding.destination_port)
                if port_str not in iocs["ports"]:
                    iocs["ports"].append(port_str)

        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            statistics={
                "port_scan_threshold": self.port_scan_threshold,
                "brute_force_threshold": self.brute_force_threshold,
            },
            iocs=iocs,
        )

    def _detect_port_scan(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """
        Detect port scanning activity.

        Port scans are identified by a single source IP connecting to
        many different ports on target hosts within a short time window.
        """
        findings: list[Finding] = []

        # Track ports per source IP within time windows
        ip_port_access: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        ip_first_seen: dict[str, float] = {}

        for packet in pcap_data.packets:
            if not packet.src_ip or not packet.dst_port:
                continue

            key = f"{packet.src_ip}->{packet.dst_ip}"

            if key not in ip_first_seen:
                ip_first_seen[key] = packet.timestamp

            # Only count within time window
            if packet.timestamp - ip_first_seen[key] <= self.port_scan_window:
                ip_port_access[packet.src_ip][packet.dst_ip].add(packet.dst_port)

        # Detect scans
        for src_ip, targets in ip_port_access.items():
            for dst_ip, ports in targets.items():
                if len(ports) >= self.port_scan_threshold:
                    # Classify scan type
                    scan_type = self._classify_scan_type(ports)

                    findings.append(
                        self._create_finding(
                            title=f"Port Scan Detected: {scan_type}",
                            description=(
                                f"Host {src_ip} scanned {len(ports)} ports on "
                                f"{dst_ip} within {self.port_scan_window} seconds. "
                                f"This indicates network reconnaissance activity."
                            ),
                            severity=Severity.HIGH,
                            category="Port Scan",
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            evidence=[
                                f"Scan type: {scan_type}",
                                f"Ports scanned: {len(ports)}",
                                f"Sample ports: {sorted(list(ports))[:10]}",
                            ],
                            recommendations=[
                                "Block the source IP at the firewall",
                                "Review IDS/IPS logs for additional context",
                                "Check if this is authorized penetration testing",
                                "Implement port scan detection rules",
                            ],
                            mitre_technique="T1046",
                            mitre_tactic="Discovery",
                        )
                    )

        return findings

    def _classify_scan_type(self, ports: set[int]) -> str:
        """Classify the type of port scan based on ports accessed."""
        sorted_ports = sorted(ports)

        # Check for sequential scan
        if len(sorted_ports) > 10:
            sequential = sum(
                1 for i in range(len(sorted_ports) - 1)
                if sorted_ports[i + 1] - sorted_ports[i] == 1
            )
            if sequential > len(sorted_ports) * 0.8:
                return "Sequential Scan"

        # Check for common ports only
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080}
        if ports.issubset(common_ports):
            return "Common Ports Scan"

        # Check for top ports
        top_ports = {22, 80, 443, 21, 25, 3389, 110, 445, 139, 143}
        if len(ports.intersection(top_ports)) > len(ports) * 0.5:
            return "Top Ports Scan"

        return "Full Port Scan"

    def _detect_brute_force(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """
        Detect brute force authentication attempts.

        Identifies repeated connection attempts to authentication services
        (SSH, FTP, RDP, etc.) from the same source.
        """
        findings: list[Finding] = []

        # Ports associated with authentication
        auth_ports = {
            22: "SSH",
            23: "Telnet",
            21: "FTP",
            3389: "RDP",
            5900: "VNC",
            3306: "MySQL",
            1433: "MSSQL",
            5432: "PostgreSQL",
            389: "LDAP",
            636: "LDAPS",
        }

        # Track attempts per source IP and service
        attempts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

        for conn in pcap_data.connections.values():
            if conn.dst_port in auth_ports:
                attempts[conn.src_ip][conn.dst_port] += conn.packet_count

        # Detect brute force
        for src_ip, port_attempts in attempts.items():
            for port, count in port_attempts.items():
                if count >= self.brute_force_threshold:
                    service = auth_ports[port]
                    findings.append(
                        self._create_finding(
                            title=f"Potential Brute Force Attack: {service}",
                            description=(
                                f"Detected {count} connection attempts from {src_ip} "
                                f"to {service} service (port {port}). This pattern is "
                                f"consistent with password brute forcing."
                            ),
                            severity=Severity.HIGH,
                            category="Brute Force",
                            source_ip=src_ip,
                            destination_port=port,
                            protocol=service,
                            evidence=[
                                f"Service: {service}",
                                f"Port: {port}",
                                f"Attempt count: {count}",
                            ],
                            recommendations=[
                                f"Block {src_ip} at the firewall",
                                "Implement account lockout policies",
                                "Enable multi-factor authentication",
                                "Review authentication logs for successful compromises",
                                "Consider using fail2ban or similar tools",
                            ],
                            mitre_technique="T1110",
                            mitre_tactic="Credential Access",
                        )
                    )

        return findings

    def _detect_sql_injection(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect SQL injection attempts in HTTP traffic."""
        findings: list[Finding] = []

        sql_patterns = [
            "' OR '1'='1",
            "' OR 1=1",
            "'; DROP",
            "UNION SELECT",
            "' AND '",
            "1=1--",
            "admin'--",
            "' OR ''='",
            "'; EXEC",
            "xp_cmdshell",
        ]

        for http in pcap_data.http_requests:
            uri_lower = http.uri.lower()
            for pattern in sql_patterns:
                if pattern.lower() in uri_lower:
                    findings.append(
                        self._create_finding(
                            title="SQL Injection Attempt Detected",
                            description=(
                                f"Detected SQL injection pattern in HTTP request "
                                f"from {http.src_ip} to {http.dst_ip}. "
                                f"URI: {http.uri[:100]}..."
                            ),
                            severity=Severity.CRITICAL,
                            category="SQL Injection",
                            source_ip=http.src_ip,
                            destination_ip=http.dst_ip,
                            timestamp=http.timestamp,
                            evidence=[
                                f"Pattern: {pattern}",
                                f"URI: {http.uri}",
                                f"Method: {http.method}",
                            ],
                            recommendations=[
                                "Block the source IP",
                                "Review web application logs",
                                "Implement WAF rules",
                                "Use parameterized queries",
                                "Audit database for unauthorized access",
                            ],
                            mitre_technique="T1190",
                            mitre_tactic="Initial Access",
                        )
                    )
                    break

        return findings

    def _detect_directory_traversal(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect directory traversal attempts."""
        findings: list[Finding] = []

        traversal_patterns = [
            "../",
            "..\\",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            "..%5c",
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows",
            "boot.ini",
        ]

        for http in pcap_data.http_requests:
            uri_lower = http.uri.lower()
            for pattern in traversal_patterns:
                if pattern.lower() in uri_lower:
                    findings.append(
                        self._create_finding(
                            title="Directory Traversal Attempt Detected",
                            description=(
                                f"Detected path traversal attempt in HTTP request "
                                f"from {http.src_ip}. Attacker may be trying to "
                                f"access files outside the web root."
                            ),
                            severity=Severity.HIGH,
                            category="Directory Traversal",
                            source_ip=http.src_ip,
                            destination_ip=http.dst_ip,
                            timestamp=http.timestamp,
                            evidence=[
                                f"Pattern: {pattern}",
                                f"URI: {http.uri}",
                            ],
                            recommendations=[
                                "Block the source IP",
                                "Validate and sanitize file paths",
                                "Implement proper access controls",
                                "Use WAF to block traversal attempts",
                            ],
                            mitre_technique="T1083",
                            mitre_tactic="Discovery",
                        )
                    )
                    break

        return findings

    def _detect_command_injection(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect command injection attempts."""
        findings: list[Finding] = []

        cmd_patterns = [
            "; cat",
            "| cat",
            "`cat",
            "$(cat",
            "; ls",
            "| ls",
            "; id",
            "| id",
            "; whoami",
            "| whoami",
            "; nc ",
            "| nc ",
            "; wget",
            "| wget",
            "; curl",
            "| curl",
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
            "powershell",
        ]

        for http in pcap_data.http_requests:
            uri_lower = http.uri.lower()
            for pattern in cmd_patterns:
                if pattern.lower() in uri_lower:
                    findings.append(
                        self._create_finding(
                            title="Command Injection Attempt Detected",
                            description=(
                                f"Detected command injection pattern in HTTP request "
                                f"from {http.src_ip}. Attacker may be trying to "
                                f"execute system commands."
                            ),
                            severity=Severity.CRITICAL,
                            category="Command Injection",
                            source_ip=http.src_ip,
                            destination_ip=http.dst_ip,
                            timestamp=http.timestamp,
                            evidence=[
                                f"Pattern: {pattern}",
                                f"URI: {http.uri}",
                            ],
                            recommendations=[
                                "Block the source IP immediately",
                                "Validate and sanitize all user input",
                                "Implement proper input validation",
                                "Review system logs for compromise",
                            ],
                            mitre_technique="T1059",
                            mitre_tactic="Execution",
                        )
                    )
                    break

        return findings

    def _detect_dos_patterns(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect DoS/DDoS patterns based on traffic characteristics."""
        findings: list[Finding] = []

        # Calculate packets per second
        duration = pcap_data.duration
        if duration <= 0:
            return findings

        pps = pcap_data.packet_count / duration

        # Extreme traffic rates
        if pps > 10000:
            # Check for SYN flood (would need TCP flags)
            findings.append(
                self._create_finding(
                    title="Potential DoS Attack Detected",
                    description=(
                        f"Extremely high packet rate detected: {pps:.0f} packets/second. "
                        f"This traffic volume is consistent with a DoS attack."
                    ),
                    severity=Severity.CRITICAL,
                    category="Denial of Service",
                    evidence=[
                        f"Packets per second: {pps:.0f}",
                        f"Total packets: {pcap_data.packet_count}",
                        f"Duration: {duration:.1f} seconds",
                    ],
                    recommendations=[
                        "Enable rate limiting",
                        "Contact upstream provider for DDoS mitigation",
                        "Identify and block source IPs",
                        "Enable SYN cookies if SYN flood",
                    ],
                    mitre_technique="T1498",
                    mitre_tactic="Impact",
                )
            )

        # Check for amplification attacks (unusual protocol ratios)
        dns_count = pcap_data.protocol_counts.get("DNS", 0)
        if dns_count > pcap_data.packet_count * 0.8:
            findings.append(
                self._create_finding(
                    title="Potential DNS Amplification Attack",
                    description=(
                        f"DNS traffic comprises {dns_count/pcap_data.packet_count*100:.1f}% "
                        f"of total traffic. This is consistent with DNS amplification attack."
                    ),
                    severity=Severity.CRITICAL,
                    category="DDoS - Amplification",
                    protocol="DNS",
                    evidence=[
                        f"DNS packets: {dns_count}",
                        f"Total packets: {pcap_data.packet_count}",
                        f"DNS ratio: {dns_count/pcap_data.packet_count*100:.1f}%",
                    ],
                    recommendations=[
                        "Block DNS responses from external sources",
                        "Implement response rate limiting on DNS servers",
                        "Enable BCP38 filtering",
                    ],
                    mitre_technique="T1498.002",
                    mitre_tactic="Impact",
                )
            )

        return findings
