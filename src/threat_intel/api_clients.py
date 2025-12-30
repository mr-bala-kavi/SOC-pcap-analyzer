"""API clients for external threat intelligence services."""

import time
from dataclasses import dataclass
from typing import Any, Optional

import requests

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ThreatIntelResult:
    """Result from threat intelligence lookup."""

    indicator: str
    indicator_type: str  # ip, domain, hash
    is_malicious: bool
    confidence_score: int  # 0-100
    source: str
    categories: list[str]
    additional_info: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "is_malicious": self.is_malicious,
            "confidence_score": self.confidence_score,
            "source": self.source,
            "categories": self.categories,
            "additional_info": self.additional_info,
        }


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, calls_per_minute: int):
        """
        Initialize rate limiter.

        Args:
            calls_per_minute: Maximum API calls per minute
        """
        self.calls_per_minute = calls_per_minute
        self.interval = 60.0 / calls_per_minute if calls_per_minute > 0 else 0
        self.last_call: float = 0

    def wait(self) -> None:
        """Wait if necessary to respect rate limit."""
        if self.interval <= 0:
            return

        now = time.time()
        elapsed = now - self.last_call
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_call = time.time()


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str,
        rate_limit: int = 4,
        enabled: bool = True,
    ):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key
            rate_limit: Requests per minute (free tier = 4)
            enabled: Whether to enable API lookups
        """
        self.api_key = api_key
        self.enabled = enabled and bool(api_key)
        self.rate_limiter = RateLimiter(rate_limit)
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Look up IP reputation in VirusTotal.

        Args:
            ip: IP address to check

        Returns:
            ThreatIntelResult or None if lookup fails
        """
        if not self.enabled:
            return None

        try:
            self.rate_limiter.wait()
            response = self.session.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1

                is_malicious = malicious > 0 or suspicious > 2
                confidence = int((malicious + suspicious) / total * 100) if total else 0

                return ThreatIntelResult(
                    indicator=ip,
                    indicator_type="ip",
                    is_malicious=is_malicious,
                    confidence_score=confidence,
                    source="VirusTotal",
                    categories=self._extract_categories(attributes),
                    additional_info={
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": stats.get("harmless", 0),
                        "as_owner": attributes.get("as_owner", "Unknown"),
                        "country": attributes.get("country", "Unknown"),
                    },
                )
            elif response.status_code == 404:
                logger.debug(f"IP {ip} not found in VirusTotal")
                return None
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Look up domain reputation in VirusTotal.

        Args:
            domain: Domain to check

        Returns:
            ThreatIntelResult or None if lookup fails
        """
        if not self.enabled:
            return None

        try:
            self.rate_limiter.wait()
            response = self.session.get(
                f"{self.BASE_URL}/domains/{domain}",
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1

                is_malicious = malicious > 0 or suspicious > 2
                confidence = int((malicious + suspicious) / total * 100) if total else 0

                return ThreatIntelResult(
                    indicator=domain,
                    indicator_type="domain",
                    is_malicious=is_malicious,
                    confidence_score=confidence,
                    source="VirusTotal",
                    categories=self._extract_categories(attributes),
                    additional_info={
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "registrar": attributes.get("registrar", "Unknown"),
                        "creation_date": attributes.get("creation_date", "Unknown"),
                    },
                )
            elif response.status_code == 404:
                logger.debug(f"Domain {domain} not found in VirusTotal")
                return None
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def lookup_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """
        Look up file hash reputation in VirusTotal.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            ThreatIntelResult or None if lookup fails
        """
        if not self.enabled:
            return None

        try:
            self.rate_limiter.wait()
            response = self.session.get(
                f"{self.BASE_URL}/files/{file_hash}",
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1

                is_malicious = malicious > 0
                confidence = int((malicious + suspicious) / total * 100) if total else 0

                return ThreatIntelResult(
                    indicator=file_hash,
                    indicator_type="hash",
                    is_malicious=is_malicious,
                    confidence_score=confidence,
                    source="VirusTotal",
                    categories=attributes.get("tags", []),
                    additional_info={
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "file_type": attributes.get("type_description", "Unknown"),
                        "file_name": attributes.get("meaningful_name", "Unknown"),
                    },
                )
            elif response.status_code == 404:
                logger.debug(f"Hash {file_hash} not found in VirusTotal")
                return None
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def _extract_categories(self, attributes: dict[str, Any]) -> list[str]:
        """Extract categories from VirusTotal attributes."""
        categories = []
        cats = attributes.get("categories", {})
        if isinstance(cats, dict):
            categories = list(set(cats.values()))
        elif isinstance(cats, list):
            categories = cats
        return categories


class AbuseIPDBClient:
    """Client for AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        api_key: str,
        rate_limit: int = 1000,
        confidence_threshold: int = 50,
        enabled: bool = True,
    ):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key
            rate_limit: Requests per day (free tier = 1000)
            confidence_threshold: Minimum confidence to flag as malicious
            enabled: Whether to enable API lookups
        """
        self.api_key = api_key
        self.enabled = enabled and bool(api_key)
        self.confidence_threshold = confidence_threshold
        # Convert daily limit to per-minute (approximate)
        self.rate_limiter = RateLimiter(int(rate_limit / 1440) + 1)
        self.session = requests.Session()
        self.session.headers.update({
            "Key": api_key,
            "Accept": "application/json",
        })

    def lookup_ip(self, ip: str, max_age_days: int = 90) -> Optional[ThreatIntelResult]:
        """
        Check IP reputation in AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports to consider

        Returns:
            ThreatIntelResult or None if lookup fails
        """
        if not self.enabled:
            return None

        try:
            self.rate_limiter.wait()
            response = self.session.get(
                f"{self.BASE_URL}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                },
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                confidence = data.get("abuseConfidenceScore", 0)
                is_malicious = confidence >= self.confidence_threshold

                # Map category IDs to names
                categories = self._map_categories(data.get("usageType", ""))

                return ThreatIntelResult(
                    indicator=ip,
                    indicator_type="ip",
                    is_malicious=is_malicious,
                    confidence_score=confidence,
                    source="AbuseIPDB",
                    categories=categories,
                    additional_info={
                        "total_reports": data.get("totalReports", 0),
                        "num_distinct_users": data.get("numDistinctUsers", 0),
                        "country_code": data.get("countryCode", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "domain": data.get("domain", "Unknown"),
                        "is_tor": data.get("isTor", False),
                        "is_public": data.get("isPublic", True),
                    },
                )
            elif response.status_code == 422:
                logger.debug(f"Invalid IP format: {ip}")
                return None
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"AbuseIPDB request failed: {e}")
            return None

    def _map_categories(self, usage_type: str) -> list[str]:
        """Map AbuseIPDB usage type to categories."""
        if not usage_type:
            return []
        return [usage_type]


class ThreatIntelAggregator:
    """Aggregate results from multiple threat intelligence sources."""

    def __init__(
        self,
        virustotal: Optional[VirusTotalClient] = None,
        abuseipdb: Optional[AbuseIPDBClient] = None,
    ):
        """
        Initialize aggregator with clients.

        Args:
            virustotal: VirusTotal client
            abuseipdb: AbuseIPDB client
        """
        self.virustotal = virustotal
        self.abuseipdb = abuseipdb

    def lookup_ip(self, ip: str) -> list[ThreatIntelResult]:
        """
        Look up IP in all available sources.

        Args:
            ip: IP address to check

        Returns:
            List of results from all sources
        """
        results = []

        if self.virustotal:
            vt_result = self.virustotal.lookup_ip(ip)
            if vt_result:
                results.append(vt_result)

        if self.abuseipdb:
            aipdb_result = self.abuseipdb.lookup_ip(ip)
            if aipdb_result:
                results.append(aipdb_result)

        return results

    def lookup_domain(self, domain: str) -> list[ThreatIntelResult]:
        """
        Look up domain in all available sources.

        Args:
            domain: Domain to check

        Returns:
            List of results from all sources
        """
        results = []

        if self.virustotal:
            vt_result = self.virustotal.lookup_domain(domain)
            if vt_result:
                results.append(vt_result)

        return results

    def is_malicious(self, results: list[ThreatIntelResult]) -> bool:
        """
        Determine if indicator is malicious based on aggregated results.

        Args:
            results: List of threat intel results

        Returns:
            True if any source flags as malicious with high confidence
        """
        for result in results:
            if result.is_malicious and result.confidence_score >= 50:
                return True
        return False

    def get_max_confidence(self, results: list[ThreatIntelResult]) -> int:
        """Get maximum confidence score from results."""
        if not results:
            return 0
        return max(r.confidence_score for r in results)
