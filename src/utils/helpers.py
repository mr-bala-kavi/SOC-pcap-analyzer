"""Helper utilities for SOC PCAP Analyzer."""

import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml


def load_config(config_path: str = "config.yaml") -> dict[str, Any]:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(path, "r") as f:
        return yaml.safe_load(f)


def format_bytes(size: int) -> str:
    """
    Format byte size into human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Human-readable size string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_timestamp(timestamp: float, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format Unix timestamp into human-readable string.

    Args:
        timestamp: Unix timestamp
        fmt: Output format string

    Returns:
        Formatted datetime string
    """
    return datetime.fromtimestamp(timestamp).strftime(fmt)


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private (RFC 1918).

    Args:
        ip: IP address string

    Returns:
        True if IP is private, False otherwise
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def is_whitelisted(
    ip: str,
    whitelist_ips: Optional[list[str]] = None,
    whitelist_networks: Optional[list[str]] = None,
) -> bool:
    """
    Check if an IP is in the whitelist.

    Args:
        ip: IP address to check
        whitelist_ips: List of whitelisted IP addresses
        whitelist_networks: List of whitelisted CIDR networks

    Returns:
        True if IP is whitelisted
    """
    whitelist_ips = whitelist_ips or []
    whitelist_networks = whitelist_networks or []

    if ip in whitelist_ips:
        return True

    try:
        addr = ipaddress.ip_address(ip)
        for network in whitelist_networks:
            if addr in ipaddress.ip_network(network, strict=False):
                return True
    except ValueError:
        pass

    return False


def get_protocol_name(protocol_num: int) -> str:
    """
    Get protocol name from protocol number.

    Args:
        protocol_num: IP protocol number

    Returns:
        Protocol name string
    """
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        89: "OSPF",
        132: "SCTP",
    }
    return protocols.get(protocol_num, f"Protocol-{protocol_num}")


def parse_port_range(port_str: str) -> list[int]:
    """
    Parse port range string into list of ports.

    Args:
        port_str: Port string (e.g., "80", "80-443", "22,80,443")

    Returns:
        List of port numbers
    """
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value (0-8 for bytes)
    """
    if not data:
        return 0.0

    from collections import Counter
    import math

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
