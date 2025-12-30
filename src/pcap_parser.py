"""PCAP parsing module using tshark and scapy."""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator, Optional

from .utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Packet:
    """Represents a parsed network packet."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    info: str = ""
    raw_data: Optional[dict[str, Any]] = None


@dataclass
class Connection:
    """Represents a network connection/flow."""

    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_count: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    packets: list[Packet] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Calculate connection duration in seconds."""
        return self.end_time - self.start_time if self.end_time > self.start_time else 0.0

    @property
    def connection_key(self) -> str:
        """Generate unique connection identifier."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"


@dataclass
class DNSQuery:
    """Represents a DNS query."""

    timestamp: float
    src_ip: str
    query_name: str
    query_type: str
    response_ips: list[str] = field(default_factory=list)


@dataclass
class HTTPRequest:
    """Represents an HTTP request."""

    timestamp: float
    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    user_agent: str = ""
    status_code: Optional[int] = None


@dataclass
class ParsedPCAP:
    """Container for all parsed PCAP data."""

    file_path: str
    packet_count: int
    start_time: float
    end_time: float
    packets: list[Packet]
    connections: dict[str, Connection]
    dns_queries: list[DNSQuery]
    http_requests: list[HTTPRequest]
    unique_ips: set[str]
    unique_ports: set[int]
    protocol_counts: dict[str, int]

    @property
    def duration(self) -> float:
        """Total capture duration in seconds."""
        return self.end_time - self.start_time if self.end_time > self.start_time else 0.0


class PCAPParser:
    """Parse PCAP files using tshark for efficiency."""

    # tshark fields to extract
    TSHARK_FIELDS = [
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "ip.proto",
        "_ws.col.Protocol",
        "_ws.col.Info",
        "dns.qry.name",
        "dns.qry.type",
        "dns.a",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
        "http.response.code",
    ]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """
        Initialize PCAP parser.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.chunk_size = self.config.get("analysis", {}).get("chunk_size", 10000)
        self.max_packets = self.config.get("analysis", {}).get("max_packets", 0)
        self._verify_tshark()

    def _verify_tshark(self) -> None:
        """Verify tshark is available."""
        try:
            result = subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError("tshark not available")
            logger.debug(f"tshark version: {result.stdout.split(chr(10))[0]}")
        except FileNotFoundError:
            raise RuntimeError("tshark not found. Please install Wireshark/tshark.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark version check timed out")

    def parse(self, pcap_path: str) -> ParsedPCAP:
        """
        Parse a PCAP file and extract network data.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            ParsedPCAP object containing all parsed data

        Raises:
            FileNotFoundError: If PCAP file doesn't exist
            RuntimeError: If parsing fails
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.info(f"Parsing PCAP file: {pcap_path}")

        packets: list[Packet] = []
        connections: dict[str, Connection] = {}
        dns_queries: list[DNSQuery] = []
        http_requests: list[HTTPRequest] = []
        unique_ips: set[str] = set()
        unique_ports: set[int] = set()
        protocol_counts: dict[str, int] = {}

        start_time = float("inf")
        end_time = 0.0
        packet_count = 0

        for packet in self._stream_packets(pcap_path):
            packets.append(packet)
            packet_count += 1

            # Track time range
            if packet.timestamp < start_time:
                start_time = packet.timestamp
            if packet.timestamp > end_time:
                end_time = packet.timestamp

            # Track unique IPs
            if packet.src_ip:
                unique_ips.add(packet.src_ip)
            if packet.dst_ip:
                unique_ips.add(packet.dst_ip)

            # Track unique ports
            if packet.src_port:
                unique_ports.add(packet.src_port)
            if packet.dst_port:
                unique_ports.add(packet.dst_port)

            # Track protocol counts
            protocol_counts[packet.protocol] = protocol_counts.get(packet.protocol, 0) + 1

            # Build connections
            conn_key = self._get_connection_key(packet)
            if conn_key:
                if conn_key not in connections:
                    connections[conn_key] = Connection(
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        src_port=packet.src_port,
                        dst_port=packet.dst_port,
                        protocol=packet.protocol,
                        start_time=packet.timestamp,
                    )
                conn = connections[conn_key]
                conn.packet_count += 1
                conn.total_bytes += packet.length
                conn.end_time = packet.timestamp

            # Extract DNS queries
            if packet.raw_data and packet.raw_data.get("dns_query"):
                dns_queries.append(
                    DNSQuery(
                        timestamp=packet.timestamp,
                        src_ip=packet.src_ip,
                        query_name=packet.raw_data["dns_query"],
                        query_type=packet.raw_data.get("dns_type", "A"),
                        response_ips=packet.raw_data.get("dns_answers", []),
                    )
                )

            # Extract HTTP requests
            if packet.raw_data and packet.raw_data.get("http_method"):
                http_requests.append(
                    HTTPRequest(
                        timestamp=packet.timestamp,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        method=packet.raw_data["http_method"],
                        host=packet.raw_data.get("http_host", ""),
                        uri=packet.raw_data.get("http_uri", ""),
                        user_agent=packet.raw_data.get("http_user_agent", ""),
                        status_code=packet.raw_data.get("http_status"),
                    )
                )

            # Check max packets limit
            if self.max_packets > 0 and packet_count >= self.max_packets:
                logger.warning(f"Reached max packet limit: {self.max_packets}")
                break

        if start_time == float("inf"):
            start_time = 0.0

        logger.info(f"Parsed {packet_count} packets, {len(connections)} connections")

        return ParsedPCAP(
            file_path=pcap_path,
            packet_count=packet_count,
            start_time=start_time,
            end_time=end_time,
            packets=packets,
            connections=connections,
            dns_queries=dns_queries,
            http_requests=http_requests,
            unique_ips=unique_ips,
            unique_ports=unique_ports,
            protocol_counts=protocol_counts,
        )

    def _stream_packets(self, pcap_path: str) -> Generator[Packet, None, None]:
        """
        Stream packets from PCAP using tshark.

        Args:
            pcap_path: Path to PCAP file

        Yields:
            Packet objects
        """
        fields_args = []
        for field in self.TSHARK_FIELDS:
            fields_args.extend(["-e", field])

        cmd = [
            "tshark",
            "-r", pcap_path,
            "-T", "json",
            "-n",  # Disable name resolution
        ] + fields_args

        logger.debug(f"Running tshark command: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Read JSON output
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logger.error(f"tshark error: {stderr}")
                raise RuntimeError(f"tshark failed: {stderr}")

            if stdout.strip():
                try:
                    packets_json = json.loads(stdout)
                    for pkt_json in packets_json:
                        packet = self._parse_tshark_packet(pkt_json)
                        if packet:
                            yield packet
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse tshark JSON: {e}")
                    raise RuntimeError(f"Failed to parse tshark output: {e}")

        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error: {e}")
            raise RuntimeError(f"Failed to run tshark: {e}")

    def _parse_tshark_packet(self, pkt_json: dict[str, Any]) -> Optional[Packet]:
        """
        Parse a single packet from tshark JSON output.

        Args:
            pkt_json: tshark JSON packet data

        Returns:
            Packet object or None if parsing fails
        """
        try:
            layers = pkt_json.get("_source", {}).get("layers", {})

            # Get timestamp
            timestamp = float(self._get_field(layers, "frame.time_epoch", "0"))

            # Get IPs (prefer IPv4, fallback to IPv6)
            src_ip = self._get_field(layers, "ip.src") or self._get_field(layers, "ipv6.src") or ""
            dst_ip = self._get_field(layers, "ip.dst") or self._get_field(layers, "ipv6.dst") or ""

            # Get ports
            src_port = self._get_port(layers, "tcp.srcport") or self._get_port(layers, "udp.srcport")
            dst_port = self._get_port(layers, "tcp.dstport") or self._get_port(layers, "udp.dstport")

            # Get protocol and info
            protocol = self._get_field(layers, "_ws.col.Protocol", "Unknown")
            info = self._get_field(layers, "_ws.col.Info", "")
            length = int(self._get_field(layers, "frame.len", "0"))

            # Build raw data for additional info
            raw_data: dict[str, Any] = {}

            # DNS data
            dns_query = self._get_field(layers, "dns.qry.name")
            if dns_query:
                raw_data["dns_query"] = dns_query
                raw_data["dns_type"] = self._get_field(layers, "dns.qry.type", "1")
                dns_answers = self._get_field(layers, "dns.a")
                if dns_answers:
                    raw_data["dns_answers"] = (
                        dns_answers if isinstance(dns_answers, list) else [dns_answers]
                    )

            # HTTP data
            http_method = self._get_field(layers, "http.request.method")
            if http_method:
                raw_data["http_method"] = http_method
                raw_data["http_host"] = self._get_field(layers, "http.host", "")
                raw_data["http_uri"] = self._get_field(layers, "http.request.uri", "")
                raw_data["http_user_agent"] = self._get_field(layers, "http.user_agent", "")

            http_status = self._get_field(layers, "http.response.code")
            if http_status:
                raw_data["http_status"] = int(http_status)

            return Packet(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                info=info,
                raw_data=raw_data if raw_data else None,
            )

        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Failed to parse packet: {e}")
            return None

    def _get_field(
        self, layers: dict[str, Any], field: str, default: str = ""
    ) -> str:
        """Get a field value from tshark layers."""
        value = layers.get(field)
        if value is None:
            return default
        if isinstance(value, list):
            return value[0] if value else default
        return str(value)

    def _get_port(self, layers: dict[str, Any], field: str) -> Optional[int]:
        """Get a port number from tshark layers."""
        value = self._get_field(layers, field)
        if value:
            try:
                return int(value)
            except ValueError:
                pass
        return None

    def _get_connection_key(self, packet: Packet) -> Optional[str]:
        """Generate a connection key for a packet."""
        if not packet.src_ip or not packet.dst_ip:
            return None

        # Normalize direction (smaller IP first)
        if packet.src_ip < packet.dst_ip:
            return f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}/{packet.protocol}"
        else:
            return f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}/{packet.protocol}"


def get_pcap_info(pcap_path: str) -> dict[str, Any]:
    """
    Get basic information about a PCAP file without full parsing.

    Args:
        pcap_path: Path to PCAP file

    Returns:
        Dictionary with file info
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Get packet count using capinfos
    try:
        result = subprocess.run(
            ["capinfos", "-c", "-M", pcap_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        packet_count = 0
        for line in result.stdout.split("\n"):
            if "Number of packets" in line:
                packet_count = int(line.split(":")[-1].strip())
                break
    except (subprocess.SubprocessError, ValueError):
        packet_count = -1

    return {
        "file_path": str(path.absolute()),
        "file_size": path.stat().st_size,
        "packet_count": packet_count,
    }
