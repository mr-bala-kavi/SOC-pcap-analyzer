"""Known threat signatures and patterns database."""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ThreatSignature:
    """Represents a known threat signature."""

    signature_id: str
    name: str
    category: str
    severity: str
    description: str
    indicators: dict[str, Any]
    mitre_techniques: list[str]
    references: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "signature_id": self.signature_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "indicators": self.indicators,
            "mitre_techniques": self.mitre_techniques,
            "references": self.references,
        }


class KnownThreats:
    """Database of known threat signatures and patterns."""

    # Known C2 frameworks and their signatures
    C2_SIGNATURES: dict[str, ThreatSignature] = {
        "cobalt_strike": ThreatSignature(
            signature_id="C2-001",
            name="Cobalt Strike Beacon",
            category="C2 Framework",
            severity="critical",
            description="Cobalt Strike is a commercial adversary simulation tool often abused by threat actors.",
            indicators={
                "default_ports": [80, 443, 8080, 8443],
                "beacon_intervals": [60, 300, 900],  # seconds
                "user_agents": [
                    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
                    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0)",
                ],
                "uri_patterns": ["/submit.php", "/pixel.gif", "/__utm.gif", "/updates.rss"],
            },
            mitre_techniques=["T1071.001", "T1573"],
            references=[
                "https://www.cobaltstrike.com/",
                "https://attack.mitre.org/software/S0154/",
            ],
        ),
        "metasploit": ThreatSignature(
            signature_id="C2-002",
            name="Metasploit Framework",
            category="C2 Framework",
            severity="critical",
            description="Metasploit is a penetration testing framework that can be abused for malicious purposes.",
            indicators={
                "default_ports": [4444, 4445, 5555, 8080],
                "reverse_shell_ports": [4444, 5555],
                "uri_patterns": ["/handler", "/meterpreter"],
            },
            mitre_techniques=["T1059", "T1071"],
            references=[
                "https://www.metasploit.com/",
                "https://attack.mitre.org/software/S0081/",
            ],
        ),
        "empire": ThreatSignature(
            signature_id="C2-003",
            name="PowerShell Empire",
            category="C2 Framework",
            severity="critical",
            description="PowerShell Empire is a post-exploitation agent built on cryptographically secure communications.",
            indicators={
                "default_ports": [80, 443],
                "user_agents": ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"],
                "uri_patterns": ["/admin/get.php", "/news.php", "/login/process.php"],
            },
            mitre_techniques=["T1059.001", "T1071.001"],
            references=["https://attack.mitre.org/software/S0363/"],
        ),
    }

    # Known malware families
    MALWARE_SIGNATURES: dict[str, ThreatSignature] = {
        "emotet": ThreatSignature(
            signature_id="MAL-001",
            name="Emotet",
            category="Banking Trojan/Loader",
            severity="critical",
            description="Emotet is a modular banking trojan that also serves as a malware loader.",
            indicators={
                "ports": [80, 443, 8080, 7080, 20],
                "dns_patterns": ["epoch1", "epoch2", "epoch3"],
            },
            mitre_techniques=["T1566.001", "T1027", "T1071.001"],
            references=["https://attack.mitre.org/software/S0367/"],
        ),
        "trickbot": ThreatSignature(
            signature_id="MAL-002",
            name="TrickBot",
            category="Banking Trojan",
            severity="critical",
            description="TrickBot is a modular banking trojan targeting financial institutions.",
            indicators={
                "ports": [443, 447, 449],
                "uri_patterns": ["/tor/", "/onion/"],
            },
            mitre_techniques=["T1055", "T1071.001", "T1566.001"],
            references=["https://attack.mitre.org/software/S0266/"],
        ),
        "ransomware_generic": ThreatSignature(
            signature_id="MAL-003",
            name="Ransomware Activity",
            category="Ransomware",
            severity="critical",
            description="Generic ransomware indicators based on common behaviors.",
            indicators={
                "smb_patterns": ["*.encrypted", "*.locked", "README.txt"],
                "high_smb_activity": True,
            },
            mitre_techniques=["T1486", "T1490", "T1021.002"],
            references=[],
        ),
    }

    # Known reconnaissance patterns
    RECON_SIGNATURES: dict[str, ThreatSignature] = {
        "nmap_scan": ThreatSignature(
            signature_id="RECON-001",
            name="Nmap Scan",
            category="Reconnaissance",
            severity="high",
            description="Network scanning activity consistent with Nmap tool.",
            indicators={
                "tcp_flags": ["SYN", "FIN", "NULL", "XMAS"],
                "port_scan_rate": 100,  # ports per second
            },
            mitre_techniques=["T1046", "T1018"],
            references=["https://nmap.org/"],
        ),
        "masscan": ThreatSignature(
            signature_id="RECON-002",
            name="Masscan",
            category="Reconnaissance",
            severity="high",
            description="High-speed port scanning consistent with Masscan tool.",
            indicators={
                "scan_rate": 10000,  # packets per second
                "syn_only": True,
            },
            mitre_techniques=["T1046"],
            references=["https://github.com/robertdavidgraham/masscan"],
        ),
    }

    def __init__(self):
        """Initialize known threats database."""
        self.all_signatures: dict[str, ThreatSignature] = {}
        self.all_signatures.update(self.C2_SIGNATURES)
        self.all_signatures.update(self.MALWARE_SIGNATURES)
        self.all_signatures.update(self.RECON_SIGNATURES)

    def get_signature(self, signature_id: str) -> Optional[ThreatSignature]:
        """
        Get signature by ID.

        Args:
            signature_id: Signature ID

        Returns:
            ThreatSignature or None
        """
        return self.all_signatures.get(signature_id)

    def check_port(self, port: int) -> list[ThreatSignature]:
        """
        Check if port matches any known threat signatures.

        Args:
            port: Port number to check

        Returns:
            List of matching signatures
        """
        matches = []
        for sig in self.all_signatures.values():
            indicators = sig.indicators
            if port in indicators.get("default_ports", []):
                matches.append(sig)
            elif port in indicators.get("ports", []):
                matches.append(sig)
            elif port in indicators.get("reverse_shell_ports", []):
                matches.append(sig)
        return matches

    def check_user_agent(self, user_agent: str) -> list[ThreatSignature]:
        """
        Check if user agent matches any known threat signatures.

        Args:
            user_agent: User agent string

        Returns:
            List of matching signatures
        """
        matches = []
        for sig in self.all_signatures.values():
            known_uas = sig.indicators.get("user_agents", [])
            for known_ua in known_uas:
                if known_ua.lower() in user_agent.lower():
                    matches.append(sig)
                    break
        return matches

    def check_uri(self, uri: str) -> list[ThreatSignature]:
        """
        Check if URI matches any known threat signatures.

        Args:
            uri: URI path

        Returns:
            List of matching signatures
        """
        matches = []
        uri_lower = uri.lower()
        for sig in self.all_signatures.values():
            patterns = sig.indicators.get("uri_patterns", [])
            for pattern in patterns:
                if pattern.lower() in uri_lower:
                    matches.append(sig)
                    break
        return matches

    def get_signatures_by_category(self, category: str) -> list[ThreatSignature]:
        """
        Get all signatures for a category.

        Args:
            category: Category name

        Returns:
            List of signatures
        """
        return [s for s in self.all_signatures.values() if s.category == category]

    def get_all_categories(self) -> list[str]:
        """Get list of all categories."""
        return list(set(s.category for s in self.all_signatures.values()))
