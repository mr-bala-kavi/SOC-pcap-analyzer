"""Tests for PCAP parser module."""

import pytest
from unittest.mock import patch, MagicMock
import json

from src.pcap_parser import PCAPParser, Packet, Connection, ParsedPCAP


class TestPacket:
    """Tests for Packet dataclass."""

    def test_packet_creation(self):
        """Test creating a packet."""
        packet = Packet(
            timestamp=1234567890.0,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=100,
        )

        assert packet.timestamp == 1234567890.0
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.src_port == 12345
        assert packet.dst_port == 80
        assert packet.protocol == "TCP"
        assert packet.length == 100

    def test_packet_with_raw_data(self):
        """Test packet with raw data."""
        packet = Packet(
            timestamp=1234567890.0,
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol="DNS",
            length=64,
            raw_data={"dns_query": "example.com"},
        )

        assert packet.raw_data is not None
        assert packet.raw_data["dns_query"] == "example.com"


class TestConnection:
    """Tests for Connection dataclass."""

    def test_connection_creation(self):
        """Test creating a connection."""
        conn = Connection(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packet_count=10,
            total_bytes=1000,
            start_time=1234567890.0,
            end_time=1234567900.0,
        )

        assert conn.duration == 10.0
        assert conn.connection_key == "192.168.1.1:12345->192.168.1.2:80/TCP"

    def test_connection_zero_duration(self):
        """Test connection with zero duration."""
        conn = Connection(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
        )

        assert conn.duration == 0.0


class TestPCAPParser:
    """Tests for PCAPParser class."""

    @patch("subprocess.run")
    def test_verify_tshark_success(self, mock_run):
        """Test tshark verification succeeds."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="TShark (Wireshark) 4.0.0\n",
        )

        parser = PCAPParser()
        assert parser is not None

    @patch("subprocess.run")
    def test_verify_tshark_not_found(self, mock_run):
        """Test tshark verification fails when not found."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(RuntimeError, match="tshark not found"):
            PCAPParser()

    def test_get_connection_key(self):
        """Test connection key generation."""
        parser = PCAPParser.__new__(PCAPParser)

        packet = Packet(
            timestamp=0,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=100,
        )

        key = parser._get_connection_key(packet)
        assert key is not None
        assert "192.168.1.1" in key
        assert "192.168.1.2" in key

    def test_get_connection_key_no_ip(self):
        """Test connection key with missing IP."""
        parser = PCAPParser.__new__(PCAPParser)

        packet = Packet(
            timestamp=0,
            src_ip="",
            dst_ip="",
            src_port=None,
            dst_port=None,
            protocol="Unknown",
            length=100,
        )

        key = parser._get_connection_key(packet)
        assert key is None


class TestParsedPCAP:
    """Tests for ParsedPCAP dataclass."""

    def test_duration_calculation(self):
        """Test capture duration calculation."""
        pcap = ParsedPCAP(
            file_path="/test/capture.pcap",
            packet_count=100,
            start_time=1234567890.0,
            end_time=1234567990.0,
            packets=[],
            connections={},
            dns_queries=[],
            http_requests=[],
            unique_ips=set(),
            unique_ports=set(),
            protocol_counts={},
        )

        assert pcap.duration == 100.0

    def test_zero_duration(self):
        """Test zero duration when start > end."""
        pcap = ParsedPCAP(
            file_path="/test/capture.pcap",
            packet_count=0,
            start_time=100.0,
            end_time=50.0,
            packets=[],
            connections={},
            dns_queries=[],
            http_requests=[],
            unique_ips=set(),
            unique_ports=set(),
            protocol_counts={},
        )

        assert pcap.duration == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
