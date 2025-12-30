"""MITRE ATT&CK framework mapping module."""

from dataclasses import dataclass
from typing import Any, Optional

from ..analyzers.base_analyzer import Finding


@dataclass
class MitreTechnique:
    """Represents a MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactic: str
    description: str
    url: str
    detection_tips: list[str]
    mitigations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "url": self.url,
            "detection_tips": self.detection_tips,
            "mitigations": self.mitigations,
        }


class MitreMapper:
    """Map findings to MITRE ATT&CK framework."""

    # MITRE ATT&CK technique database (subset of relevant techniques)
    TECHNIQUES: dict[str, MitreTechnique] = {
        "T1046": MitreTechnique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
            description="Adversaries may attempt to get a listing of services running on remote hosts.",
            url="https://attack.mitre.org/techniques/T1046/",
            detection_tips=[
                "Monitor for unusual port scanning activity",
                "Alert on connections to many ports from single source",
                "Track failed connection attempts",
            ],
            mitigations=[
                "Network segmentation",
                "Disable unnecessary services",
                "Use host-based firewalls",
            ],
        ),
        "T1110": MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic="Credential Access",
            description="Adversaries may use brute force techniques to gain access to accounts.",
            url="https://attack.mitre.org/techniques/T1110/",
            detection_tips=[
                "Monitor authentication logs for failures",
                "Alert on multiple failed logins",
                "Track login attempts from unusual locations",
            ],
            mitigations=[
                "Account lockout policies",
                "Multi-factor authentication",
                "Strong password requirements",
                "Monitor for credential stuffing",
            ],
        ),
        "T1071": MitreTechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic="Command and Control",
            description="Adversaries may communicate using application layer protocols to avoid detection.",
            url="https://attack.mitre.org/techniques/T1071/",
            detection_tips=[
                "Monitor for unusual protocol usage",
                "Analyze traffic patterns for beaconing",
                "Inspect encrypted traffic metadata",
            ],
            mitigations=[
                "Network intrusion detection",
                "SSL/TLS inspection",
                "Application-aware firewalls",
            ],
        ),
        "T1071.001": MitreTechnique(
            technique_id="T1071.001",
            name="Web Protocols",
            tactic="Command and Control",
            description="Adversaries may communicate using web protocols (HTTP/HTTPS) for C2.",
            url="https://attack.mitre.org/techniques/T1071/001/",
            detection_tips=[
                "Monitor HTTP headers for anomalies",
                "Track unusual user agents",
                "Analyze request/response patterns",
            ],
            mitigations=[
                "Web proxy filtering",
                "SSL/TLS inspection",
                "URL categorization",
            ],
        ),
        "T1071.004": MitreTechnique(
            technique_id="T1071.004",
            name="DNS",
            tactic="Command and Control",
            description="Adversaries may communicate using DNS for C2 or data exfiltration.",
            url="https://attack.mitre.org/techniques/T1071/004/",
            detection_tips=[
                "Monitor for long DNS queries",
                "Track high-frequency DNS requests",
                "Analyze TXT record queries",
            ],
            mitigations=[
                "DNS filtering",
                "DNS query logging",
                "Block known malicious domains",
            ],
        ),
        "T1048": MitreTechnique(
            technique_id="T1048",
            name="Exfiltration Over Alternative Protocol",
            tactic="Exfiltration",
            description="Adversaries may steal data by exfiltrating it over a different protocol.",
            url="https://attack.mitre.org/techniques/T1048/",
            detection_tips=[
                "Monitor for large outbound transfers",
                "Track unusual protocol usage",
                "Analyze encrypted traffic volumes",
            ],
            mitigations=[
                "Data loss prevention",
                "Network segmentation",
                "Egress filtering",
            ],
        ),
        "T1048.003": MitreTechnique(
            technique_id="T1048.003",
            name="Exfiltration Over Unencrypted Non-C2 Protocol",
            tactic="Exfiltration",
            description="Adversaries may steal data via DNS tunneling or similar techniques.",
            url="https://attack.mitre.org/techniques/T1048/003/",
            detection_tips=[
                "Monitor DNS query lengths",
                "Track unusual DNS patterns",
                "Analyze DNS response sizes",
            ],
            mitigations=[
                "DNS filtering",
                "Limit DNS query lengths",
                "Use DNS security extensions",
            ],
        ),
        "T1190": MitreTechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Adversaries may exploit vulnerabilities in public-facing applications.",
            url="https://attack.mitre.org/techniques/T1190/",
            detection_tips=[
                "Monitor web application logs",
                "Track unusual HTTP requests",
                "Alert on known attack patterns",
            ],
            mitigations=[
                "Web application firewall",
                "Regular patching",
                "Input validation",
            ],
        ),
        "T1059": MitreTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Adversaries may abuse command and script interpreters to execute commands.",
            url="https://attack.mitre.org/techniques/T1059/",
            detection_tips=[
                "Monitor for command execution",
                "Track script interpreter usage",
                "Alert on suspicious parameters",
            ],
            mitigations=[
                "Disable or restrict scripting",
                "Application control",
                "Code signing enforcement",
            ],
        ),
        "T1021": MitreTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
            description="Adversaries may use remote services to move laterally within a network.",
            url="https://attack.mitre.org/techniques/T1021/",
            detection_tips=[
                "Monitor remote connection patterns",
                "Track authentication across systems",
                "Alert on unusual lateral activity",
            ],
            mitigations=[
                "Network segmentation",
                "Privileged access management",
                "Multi-factor authentication",
            ],
        ),
        "T1557.002": MitreTechnique(
            technique_id="T1557.002",
            name="ARP Cache Poisoning",
            tactic="Credential Access",
            description="Adversaries may poison ARP caches to position themselves for MITM attacks.",
            url="https://attack.mitre.org/techniques/T1557/002/",
            detection_tips=[
                "Monitor for duplicate MAC addresses",
                "Track ARP table changes",
                "Alert on excessive ARP traffic",
            ],
            mitigations=[
                "Dynamic ARP Inspection",
                "Static ARP entries",
                "Port security",
            ],
        ),
        "T1498": MitreTechnique(
            technique_id="T1498",
            name="Network Denial of Service",
            tactic="Impact",
            description="Adversaries may perform DoS attacks to degrade or block availability.",
            url="https://attack.mitre.org/techniques/T1498/",
            detection_tips=[
                "Monitor traffic volume anomalies",
                "Track connection rates",
                "Alert on protocol anomalies",
            ],
            mitigations=[
                "Rate limiting",
                "DDoS protection services",
                "Traffic filtering",
            ],
        ),
        "T1498.002": MitreTechnique(
            technique_id="T1498.002",
            name="Reflection Amplification",
            tactic="Impact",
            description="Adversaries may use reflection/amplification to conduct DoS attacks.",
            url="https://attack.mitre.org/techniques/T1498/002/",
            detection_tips=[
                "Monitor for amplification protocols",
                "Track unusual DNS/NTP traffic",
                "Alert on spoofed source IPs",
            ],
            mitigations=[
                "BCP38 filtering",
                "Response rate limiting",
                "Protocol restrictions",
            ],
        ),
        "T1571": MitreTechnique(
            technique_id="T1571",
            name="Non-Standard Port",
            tactic="Command and Control",
            description="Adversaries may communicate over non-standard ports to evade detection.",
            url="https://attack.mitre.org/techniques/T1571/",
            detection_tips=[
                "Monitor traffic on unusual ports",
                "Track protocol/port mismatches",
                "Alert on known C2 ports",
            ],
            mitigations=[
                "Application-aware firewalls",
                "Port-based blocking",
                "Protocol validation",
            ],
        ),
        "T1083": MitreTechnique(
            technique_id="T1083",
            name="File and Directory Discovery",
            tactic="Discovery",
            description="Adversaries may enumerate files and directories to understand the environment.",
            url="https://attack.mitre.org/techniques/T1083/",
            detection_tips=[
                "Monitor file access patterns",
                "Track directory enumeration",
                "Alert on path traversal attempts",
            ],
            mitigations=[
                "File access controls",
                "Input validation",
                "Web application firewalls",
            ],
        ),
    }

    def __init__(self):
        """Initialize MITRE mapper."""
        pass

    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """
        Get technique details by ID.

        Args:
            technique_id: MITRE technique ID (e.g., T1046)

        Returns:
            MitreTechnique or None if not found
        """
        return self.TECHNIQUES.get(technique_id)

    def map_finding(self, finding: Finding) -> Optional[MitreTechnique]:
        """
        Map a finding to its MITRE ATT&CK technique.

        Args:
            finding: Security finding

        Returns:
            MitreTechnique or None if no mapping
        """
        if finding.mitre_technique:
            return self.get_technique(finding.mitre_technique)
        return None

    def get_coverage_summary(
        self, findings: list[Finding]
    ) -> dict[str, list[MitreTechnique]]:
        """
        Get summary of MITRE ATT&CK coverage from findings.

        Args:
            findings: List of security findings

        Returns:
            Dictionary mapping tactics to techniques detected
        """
        coverage: dict[str, list[MitreTechnique]] = {}

        seen_techniques: set[str] = set()

        for finding in findings:
            if finding.mitre_technique and finding.mitre_technique not in seen_techniques:
                technique = self.get_technique(finding.mitre_technique)
                if technique:
                    tactic = technique.tactic
                    if tactic not in coverage:
                        coverage[tactic] = []
                    coverage[tactic].append(technique)
                    seen_techniques.add(finding.mitre_technique)

        return coverage

    def get_all_tactics(self) -> list[str]:
        """Get list of all tactics in order."""
        return [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]

    def get_techniques_by_tactic(self, tactic: str) -> list[MitreTechnique]:
        """
        Get all known techniques for a given tactic.

        Args:
            tactic: MITRE ATT&CK tactic name

        Returns:
            List of techniques for the tactic
        """
        return [t for t in self.TECHNIQUES.values() if t.tactic == tactic]
