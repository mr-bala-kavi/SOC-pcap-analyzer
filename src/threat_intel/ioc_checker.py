"""IOC (Indicators of Compromise) checking module."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from ..utils.logger import get_logger
from .api_clients import ThreatIntelAggregator, ThreatIntelResult

logger = get_logger(__name__)


@dataclass
class IOCMatch:
    """Represents a matched IOC."""

    indicator: str
    indicator_type: str  # ip, domain, hash, url
    source: str  # local, virustotal, abuseipdb
    category: str
    description: str
    severity: str  # critical, high, medium, low
    threat_intel_results: list[ThreatIntelResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "source": self.source,
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "threat_intel": [r.to_dict() for r in self.threat_intel_results],
        }


class IOCChecker:
    """Check network traffic against known IOCs."""

    def __init__(
        self,
        ioc_file: Optional[str] = None,
        threat_intel: Optional[ThreatIntelAggregator] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        """
        Initialize IOC checker.

        Args:
            ioc_file: Path to IOC database YAML file
            threat_intel: Threat intelligence aggregator for API lookups
            config: Configuration dictionary
        """
        self.config = config or {}
        self.threat_intel = threat_intel
        self.ioc_database = self._load_ioc_database(ioc_file)

        # Cache for API results to avoid duplicate lookups
        self._cache: dict[str, list[ThreatIntelResult]] = {}

    def _load_ioc_database(self, ioc_file: Optional[str]) -> dict[str, Any]:
        """Load IOC database from YAML file."""
        if not ioc_file:
            return self._get_default_iocs()

        path = Path(ioc_file)
        if not path.exists():
            logger.warning(f"IOC file not found: {ioc_file}, using defaults")
            return self._get_default_iocs()

        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
            return data

    def _get_default_iocs(self) -> dict[str, Any]:
        """Return default IOC database with common malicious indicators."""
        return {
            "malicious_ips": [],
            "malicious_domains": [
                # Example known malicious domains (for demonstration)
                {"domain": "malware.com", "category": "malware", "severity": "critical"},
                {"domain": "phishing.example", "category": "phishing", "severity": "high"},
            ],
            "suspicious_ports": [
                {"port": 4444, "description": "Metasploit default", "severity": "high"},
                {"port": 5555, "description": "Android ADB", "severity": "medium"},
                {"port": 31337, "description": "Back Orifice", "severity": "critical"},
                {"port": 12345, "description": "NetBus trojan", "severity": "critical"},
                {"port": 6667, "description": "IRC (common C2)", "severity": "medium"},
            ],
            "suspicious_user_agents": [
                {"pattern": "curl/", "category": "automation", "severity": "low"},
                {"pattern": "wget/", "category": "automation", "severity": "low"},
                {"pattern": "python-requests", "category": "automation", "severity": "low"},
                {"pattern": "powershell", "category": "suspicious", "severity": "high"},
            ],
        }

    def check_ip(self, ip: str, use_api: bool = True) -> Optional[IOCMatch]:
        """
        Check if IP is a known IOC.

        Args:
            ip: IP address to check
            use_api: Whether to use external API lookups

        Returns:
            IOCMatch if IP is malicious, None otherwise
        """
        # Check local database first
        for entry in self.ioc_database.get("malicious_ips", []):
            if isinstance(entry, dict):
                if entry.get("ip") == ip:
                    return IOCMatch(
                        indicator=ip,
                        indicator_type="ip",
                        source="local",
                        category=entry.get("category", "malicious"),
                        description=entry.get("description", "Known malicious IP"),
                        severity=entry.get("severity", "high"),
                    )
            elif entry == ip:
                return IOCMatch(
                    indicator=ip,
                    indicator_type="ip",
                    source="local",
                    category="malicious",
                    description="Known malicious IP",
                    severity="high",
                )

        # Check external APIs if enabled
        if use_api and self.threat_intel:
            if ip in self._cache:
                results = self._cache[ip]
            else:
                results = self.threat_intel.lookup_ip(ip)
                self._cache[ip] = results

            if results and self.threat_intel.is_malicious(results):
                return IOCMatch(
                    indicator=ip,
                    indicator_type="ip",
                    source="threat_intel",
                    category="malicious",
                    description="Flagged by threat intelligence",
                    severity="high",
                    threat_intel_results=results,
                )

        return None

    def check_domain(self, domain: str, use_api: bool = True) -> Optional[IOCMatch]:
        """
        Check if domain is a known IOC.

        Args:
            domain: Domain to check
            use_api: Whether to use external API lookups

        Returns:
            IOCMatch if domain is malicious, None otherwise
        """
        domain_lower = domain.lower()

        # Check local database
        for entry in self.ioc_database.get("malicious_domains", []):
            if isinstance(entry, dict):
                ioc_domain = entry.get("domain", "").lower()
                if ioc_domain and (domain_lower == ioc_domain or domain_lower.endswith("." + ioc_domain)):
                    return IOCMatch(
                        indicator=domain,
                        indicator_type="domain",
                        source="local",
                        category=entry.get("category", "malicious"),
                        description=entry.get("description", "Known malicious domain"),
                        severity=entry.get("severity", "high"),
                    )
            elif isinstance(entry, str):
                if domain_lower == entry.lower() or domain_lower.endswith("." + entry.lower()):
                    return IOCMatch(
                        indicator=domain,
                        indicator_type="domain",
                        source="local",
                        category="malicious",
                        description="Known malicious domain",
                        severity="high",
                    )

        # Check external APIs if enabled
        if use_api and self.threat_intel:
            cache_key = f"domain:{domain}"
            if cache_key in self._cache:
                results = self._cache[cache_key]
            else:
                results = self.threat_intel.lookup_domain(domain)
                self._cache[cache_key] = results

            if results and self.threat_intel.is_malicious(results):
                return IOCMatch(
                    indicator=domain,
                    indicator_type="domain",
                    source="threat_intel",
                    category="malicious",
                    description="Flagged by threat intelligence",
                    severity="high",
                    threat_intel_results=results,
                )

        return None

    def check_port(self, port: int) -> Optional[IOCMatch]:
        """
        Check if port is suspicious.

        Args:
            port: Port number to check

        Returns:
            IOCMatch if port is suspicious, None otherwise
        """
        for entry in self.ioc_database.get("suspicious_ports", []):
            if isinstance(entry, dict) and entry.get("port") == port:
                return IOCMatch(
                    indicator=str(port),
                    indicator_type="port",
                    source="local",
                    category="suspicious_port",
                    description=entry.get("description", "Suspicious port"),
                    severity=entry.get("severity", "medium"),
                )

        return None

    def check_user_agent(self, user_agent: str) -> Optional[IOCMatch]:
        """
        Check if user agent is suspicious.

        Args:
            user_agent: User agent string to check

        Returns:
            IOCMatch if user agent is suspicious, None otherwise
        """
        ua_lower = user_agent.lower()

        for entry in self.ioc_database.get("suspicious_user_agents", []):
            if isinstance(entry, dict):
                pattern = entry.get("pattern", "").lower()
                if pattern and pattern in ua_lower:
                    return IOCMatch(
                        indicator=user_agent,
                        indicator_type="user_agent",
                        source="local",
                        category=entry.get("category", "suspicious"),
                        description=f"Matches pattern: {pattern}",
                        severity=entry.get("severity", "low"),
                    )

        return None

    def check_all_ips(
        self, ips: list[str], use_api: bool = True, limit: int = 50
    ) -> list[IOCMatch]:
        """
        Check multiple IPs against IOC database.

        Args:
            ips: List of IP addresses to check
            use_api: Whether to use external API lookups
            limit: Maximum number of API lookups

        Returns:
            List of IOCMatch objects for malicious IPs
        """
        matches = []
        api_lookups = 0

        for ip in ips:
            # Limit API lookups
            should_use_api = use_api and api_lookups < limit

            match = self.check_ip(ip, use_api=should_use_api)
            if match:
                matches.append(match)
                if match.source == "threat_intel":
                    api_lookups += 1

        return matches

    def check_all_domains(
        self, domains: list[str], use_api: bool = True, limit: int = 50
    ) -> list[IOCMatch]:
        """
        Check multiple domains against IOC database.

        Args:
            domains: List of domains to check
            use_api: Whether to use external API lookups
            limit: Maximum number of API lookups

        Returns:
            List of IOCMatch objects for malicious domains
        """
        matches = []
        api_lookups = 0

        for domain in domains:
            should_use_api = use_api and api_lookups < limit

            match = self.check_domain(domain, use_api=should_use_api)
            if match:
                matches.append(match)
                if match.source == "threat_intel":
                    api_lookups += 1

        return matches
