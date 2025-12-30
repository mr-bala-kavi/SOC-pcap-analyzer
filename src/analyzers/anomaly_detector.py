"""Anomaly detection module for network traffic."""

from collections import defaultdict
from typing import Any, Optional

from ..pcap_parser import ParsedPCAP, Packet
from .base_analyzer import AnalysisResult, BaseAnalyzer, Finding, Severity


class AnomalyDetector(BaseAnalyzer):
    """Detect anomalies in network traffic patterns."""

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize anomaly detector."""
        super().__init__(config)
        self.name = "AnomalyDetector"

        # Load thresholds from config
        detection_config = self.config.get("detection", {})
        self.beacon_tolerance = detection_config.get("beacon_interval_tolerance", 0.1)
        self.min_beacon_count = detection_config.get("min_beacon_count", 10)
        self.exfil_threshold = detection_config.get("exfil_bytes_threshold", 10485760)
        self.dns_tunnel_length = detection_config.get("dns_tunnel_query_length", 50)

    def analyze(self, pcap_data: ParsedPCAP) -> AnalysisResult:
        """
        Analyze traffic for anomalies.

        Args:
            pcap_data: Parsed PCAP data

        Returns:
            AnalysisResult with anomaly findings
        """
        findings: list[Finding] = []
        iocs: dict[str, list[str]] = {"ips": [], "domains": []}

        # Run anomaly detections
        findings.extend(self._detect_beaconing(pcap_data))
        findings.extend(self._detect_data_exfiltration(pcap_data))
        findings.extend(self._detect_lateral_movement(pcap_data))
        findings.extend(self._detect_arp_anomalies(pcap_data))
        findings.extend(self._detect_timing_anomalies(pcap_data))

        # Collect IOCs
        for finding in findings:
            if finding.source_ip and finding.source_ip not in iocs["ips"]:
                iocs["ips"].append(finding.source_ip)
            if finding.destination_ip and finding.destination_ip not in iocs["ips"]:
                iocs["ips"].append(finding.destination_ip)

        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            statistics={
                "beacon_detection_enabled": True,
                "exfil_threshold_bytes": self.exfil_threshold,
            },
            iocs=iocs,
        )

    def _detect_beaconing(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """
        Detect C2 beaconing patterns based on connection intervals.

        Beaconing occurs when a compromised host regularly contacts
        a C2 server at consistent intervals.
        """
        findings: list[Finding] = []

        # Group packets by connection
        connection_times: dict[str, list[float]] = defaultdict(list)

        for packet in pcap_data.packets:
            if packet.src_ip and packet.dst_ip and packet.dst_port:
                key = f"{packet.src_ip}->{packet.dst_ip}:{packet.dst_port}"
                connection_times[key].append(packet.timestamp)

        # Analyze intervals for each connection
        for conn_key, times in connection_times.items():
            if len(times) < self.min_beacon_count:
                continue

            times.sort()
            intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]

            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            if avg_interval <= 0:
                continue

            # Check if intervals are consistent (low variance)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            coefficient_of_variation = std_dev / avg_interval

            # Beaconing typically has CV < tolerance
            if coefficient_of_variation < self.beacon_tolerance:
                parts = conn_key.split("->")
                src_ip = parts[0]
                dst_parts = parts[1].split(":")
                dst_ip = dst_parts[0]
                dst_port = int(dst_parts[1]) if len(dst_parts) > 1 else None

                findings.append(
                    self._create_finding(
                        title=f"Potential C2 Beaconing Detected",
                        description=(
                            f"Regular connection pattern detected from {src_ip} to "
                            f"{dst_ip}:{dst_port}. Average interval: {avg_interval:.1f}s "
                            f"with low variance (CV={coefficient_of_variation:.3f}). "
                            f"This is consistent with C2 beaconing behavior."
                        ),
                        severity=Severity.CRITICAL,
                        category="C2 Communication",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        destination_port=dst_port,
                        evidence=[
                            f"Connection count: {len(times)}",
                            f"Average interval: {avg_interval:.2f} seconds",
                            f"Coefficient of variation: {coefficient_of_variation:.4f}",
                            f"Duration: {times[-1] - times[0]:.1f} seconds",
                        ],
                        recommendations=[
                            "Isolate the affected host immediately",
                            "Block communication to the destination IP",
                            "Perform forensic analysis on the host",
                            "Check for malware and persistence mechanisms",
                        ],
                        mitre_technique="T1071",
                        mitre_tactic="Command and Control",
                    )
                )

        return findings

    def _detect_data_exfiltration(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect potential data exfiltration based on outbound data volume."""
        findings: list[Finding] = []

        # Track outbound bytes per destination
        outbound_bytes: dict[str, int] = defaultdict(int)
        outbound_connections: dict[str, list[str]] = defaultdict(list)

        for conn_key, conn in pcap_data.connections.items():
            # Consider outbound if destination port is common server port
            common_ports = {80, 443, 8080, 8443, 21, 22, 53}
            if conn.dst_port in common_ports or conn.dst_port and conn.dst_port > 1024:
                outbound_bytes[conn.dst_ip] += conn.total_bytes
                outbound_connections[conn.dst_ip].append(conn.src_ip)

        # Flag large data transfers
        for dst_ip, total_bytes in outbound_bytes.items():
            if total_bytes > self.exfil_threshold:
                src_ips = list(set(outbound_connections[dst_ip]))
                findings.append(
                    self._create_finding(
                        title=f"Potential Data Exfiltration to {dst_ip}",
                        description=(
                            f"Large data transfer detected to {dst_ip}: "
                            f"{total_bytes / (1024*1024):.2f} MB. "
                            f"This exceeds the threshold of "
                            f"{self.exfil_threshold / (1024*1024):.0f} MB and may "
                            f"indicate data exfiltration."
                        ),
                        severity=Severity.CRITICAL,
                        category="Data Exfiltration",
                        destination_ip=dst_ip,
                        evidence=[
                            f"Total bytes transferred: {total_bytes:,}",
                            f"Source IPs: {', '.join(src_ips[:5])}",
                        ],
                        recommendations=[
                            "Investigate the destination IP",
                            "Review data loss prevention logs",
                            "Check for authorized file transfers",
                            "Block the destination if unauthorized",
                        ],
                        mitre_technique="T1048",
                        mitre_tactic="Exfiltration",
                    )
                )

        return findings

    def _detect_lateral_movement(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect potential lateral movement based on internal scanning."""
        findings: list[Finding] = []

        # Track connections between internal hosts
        internal_connections: dict[str, set[str]] = defaultdict(set)

        # Common internal ranges
        internal_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168.")

        for conn_key, conn in pcap_data.connections.items():
            src_internal = any(conn.src_ip.startswith(p) for p in internal_prefixes)
            dst_internal = any(conn.dst_ip.startswith(p) for p in internal_prefixes)

            if src_internal and dst_internal and conn.src_ip != conn.dst_ip:
                internal_connections[conn.src_ip].add(conn.dst_ip)

        # Flag hosts connecting to many internal destinations
        for src_ip, destinations in internal_connections.items():
            if len(destinations) > 10:
                findings.append(
                    self._create_finding(
                        title=f"Potential Lateral Movement from {src_ip}",
                        description=(
                            f"Host {src_ip} connected to {len(destinations)} "
                            f"unique internal hosts. This pattern is consistent with "
                            f"network reconnaissance or lateral movement."
                        ),
                        severity=Severity.HIGH,
                        category="Lateral Movement",
                        source_ip=src_ip,
                        evidence=[
                            f"Unique destinations: {len(destinations)}",
                            f"Sample destinations: {', '.join(list(destinations)[:5])}",
                        ],
                        recommendations=[
                            "Investigate the source host for compromise",
                            "Review authentication logs for suspicious activity",
                            "Implement network segmentation",
                            "Enable host-based firewalls",
                        ],
                        mitre_technique="T1021",
                        mitre_tactic="Lateral Movement",
                    )
                )

        return findings

    def _detect_arp_anomalies(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect ARP-related anomalies (spoofing indicators)."""
        findings: list[Finding] = []

        # Track ARP responses - would need raw packet access
        # For now, detect based on protocol presence
        arp_count = pcap_data.protocol_counts.get("ARP", 0)

        if arp_count > 1000:
            # Excessive ARP traffic could indicate ARP flooding/spoofing
            findings.append(
                self._create_finding(
                    title="Excessive ARP Traffic Detected",
                    description=(
                        f"Detected {arp_count} ARP packets. High ARP traffic "
                        f"can indicate ARP spoofing attacks, ARP floods, or "
                        f"network reconnaissance."
                    ),
                    severity=Severity.HIGH,
                    category="ARP Anomaly",
                    protocol="ARP",
                    evidence=[f"ARP packet count: {arp_count}"],
                    recommendations=[
                        "Enable Dynamic ARP Inspection (DAI)",
                        "Implement static ARP entries for critical hosts",
                        "Deploy ARP spoofing detection tools",
                        "Monitor for duplicate IP addresses",
                    ],
                    mitre_technique="T1557.002",
                    mitre_tactic="Credential Access",
                )
            )

        return findings

    def _detect_timing_anomalies(self, pcap_data: ParsedPCAP) -> list[Finding]:
        """Detect timing-based anomalies (traffic bursts, off-hours activity)."""
        findings: list[Finding] = []

        # Analyze traffic distribution over time
        if not pcap_data.packets:
            return findings

        # Group packets by minute
        packets_per_minute: dict[int, int] = defaultdict(int)
        for packet in pcap_data.packets:
            minute = int(packet.timestamp / 60)
            packets_per_minute[minute] += 1

        if len(packets_per_minute) < 2:
            return findings

        # Calculate average and detect spikes
        avg_ppm = sum(packets_per_minute.values()) / len(packets_per_minute)
        max_ppm = max(packets_per_minute.values())

        if max_ppm > avg_ppm * 10 and max_ppm > 1000:
            findings.append(
                self._create_finding(
                    title="Traffic Spike Detected",
                    description=(
                        f"Detected a traffic spike of {max_ppm} packets/minute "
                        f"compared to average of {avg_ppm:.0f} packets/minute. "
                        f"This could indicate a burst attack, data exfiltration, "
                        f"or automated scanning."
                    ),
                    severity=Severity.MEDIUM,
                    category="Traffic Anomaly",
                    evidence=[
                        f"Peak packets/minute: {max_ppm}",
                        f"Average packets/minute: {avg_ppm:.0f}",
                        f"Spike ratio: {max_ppm/avg_ppm:.1f}x",
                    ],
                    recommendations=[
                        "Review traffic during the spike period",
                        "Check for DoS or DDoS indicators",
                        "Correlate with other security events",
                    ],
                )
            )

        return findings
