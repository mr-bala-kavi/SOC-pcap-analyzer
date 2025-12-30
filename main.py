#!/usr/bin/env python3
"""
SOC PCAP Analyzer - Automated Security Incident Analysis Tool

A comprehensive tool for analyzing PCAP files and generating
professional security incident reports.
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from src.analyzers import AttackDetector, AnomalyDetector, TrafficAnalyzer
from src.analyzers.base_analyzer import AnalysisResult
from src.pcap_parser import PCAPParser, ParsedPCAP
from src.reporting import ReportGenerator
from src.reporting.exporters import get_exporter
from src.threat_intel import IOCChecker, MitreMapper
from src.threat_intel.api_clients import (
    AbuseIPDBClient,
    ThreatIntelAggregator,
    VirusTotalClient,
)
from src.utils import load_config, setup_logger


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SOC PCAP Analyzer - Automated Security Incident Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze capture.pcap
  %(prog)s analyze capture.pcap --format pdf --output report.pdf
  %(prog)s analyze capture.pcap --quick --format markdown
  %(prog)s analyze capture.pcap -v --config custom_config.yaml
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a PCAP file and generate a report"
    )
    analyze_parser.add_argument("pcap_file", help="Path to PCAP file to analyze")
    analyze_parser.add_argument(
        "-o", "--output", help="Output file path (default: output/report.<format>)"
    )
    analyze_parser.add_argument(
        "-f",
        "--format",
        choices=["pdf", "markdown", "md", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    analyze_parser.add_argument(
        "-c", "--config", default="config.yaml", help="Configuration file path"
    )
    analyze_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    analyze_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan mode (skip some deep analysis)",
    )
    analyze_parser.add_argument(
        "--no-api",
        action="store_true",
        help="Disable external API lookups (VirusTotal, AbuseIPDB)",
    )

    # Info command
    info_parser = subparsers.add_parser("info", help="Get basic info about a PCAP file")
    info_parser.add_argument("pcap_file", help="Path to PCAP file")

    # Version
    parser.add_argument("--version", action="version", version="SOC PCAP Analyzer 1.0.0")

    return parser.parse_args()


def run_analysis(
    pcap_path: str,
    config: dict,
    quick_mode: bool = False,
    use_api: bool = True,
    verbose: bool = False,
) -> tuple[ParsedPCAP, list[AnalysisResult], float]:
    """
    Run full analysis on a PCAP file.

    Args:
        pcap_path: Path to PCAP file
        config: Configuration dictionary
        quick_mode: Enable quick scan mode
        use_api: Enable external API lookups
        verbose: Enable verbose output

    Returns:
        Tuple of (parsed_pcap, analysis_results, duration)
    """
    start_time = time.time()

    # Initialize parser
    parser = PCAPParser(config)

    # Parse PCAP
    print(f"[*] Parsing PCAP file: {pcap_path}")
    pcap_data = parser.parse(pcap_path)
    print(f"    Parsed {pcap_data.packet_count} packets, {len(pcap_data.connections)} connections")

    # Initialize analyzers
    analyzers = []

    print("[*] Running traffic analysis...")
    traffic_analyzer = TrafficAnalyzer(config)
    analyzers.append(traffic_analyzer)

    print("[*] Running anomaly detection...")
    anomaly_detector = AnomalyDetector(config)
    analyzers.append(anomaly_detector)

    print("[*] Running attack detection...")
    rules_path = Path("rules/attack_signatures.yaml")
    attack_detector = AttackDetector(
        config, rules_path=str(rules_path) if rules_path.exists() else None
    )
    analyzers.append(attack_detector)

    # Run analyzers
    results: list[AnalysisResult] = []
    for analyzer in analyzers:
        result = analyzer.analyze(pcap_data)
        results.append(result)
        if verbose:
            print(f"    {analyzer.name}: {result.finding_count} findings")

    # IOC checking
    if not quick_mode:
        print("[*] Checking IOCs...")
        threat_intel = None

        if use_api:
            ti_config = config.get("threat_intel", {})

            # Get API keys from environment variables (priority) or config file
            vt_api_key = os.getenv("VIRUSTOTAL_API_KEY") or ti_config.get("virustotal", {}).get("api_key")
            aipdb_api_key = os.getenv("ABUSEIPDB_API_KEY") or ti_config.get("abuseipdb", {}).get("api_key")

            vt_config = ti_config.get("virustotal", {})
            vt_client = None
            if vt_config.get("enabled") and vt_api_key:
                vt_client = VirusTotalClient(
                    api_key=vt_api_key,
                    rate_limit=vt_config.get("rate_limit", 4),
                )

            aipdb_config = ti_config.get("abuseipdb", {})
            aipdb_client = None
            if aipdb_config.get("enabled") and aipdb_api_key:
                aipdb_client = AbuseIPDBClient(
                    api_key=aipdb_api_key,
                    rate_limit=aipdb_config.get("rate_limit", 1000),
                )

            if vt_client or aipdb_client:
                threat_intel = ThreatIntelAggregator(
                    virustotal=vt_client,
                    abuseipdb=aipdb_client,
                )

        ioc_checker = IOCChecker(
            ioc_file="rules/ioc_lists.yaml" if Path("rules/ioc_lists.yaml").exists() else None,
            threat_intel=threat_intel,
            config=config,
        )

        # Check unique IPs (limit for performance)
        external_ips = [
            ip for ip in list(pcap_data.unique_ips)[:100]
            if not ip.startswith(("10.", "172.16.", "192.168.", "127."))
        ]

        if external_ips and verbose:
            print(f"    Checking {len(external_ips)} external IPs...")

        ioc_matches = ioc_checker.check_all_ips(external_ips, use_api=use_api, limit=20)

        if ioc_matches:
            # Add IOC findings to results
            from src.analyzers.base_analyzer import AnalysisResult, Finding, Severity

            ioc_findings = []
            for match in ioc_matches:
                ioc_findings.append(
                    Finding(
                        title=f"Malicious {match.indicator_type.upper()} Detected",
                        description=f"Indicator {match.indicator} matched: {match.description}",
                        severity=Severity.HIGH if match.severity == "high" else Severity.CRITICAL,
                        category="IOC Match",
                        source_ip=match.indicator if match.indicator_type == "ip" else None,
                        evidence=[f"Source: {match.source}", f"Category: {match.category}"],
                        recommendations=[
                            f"Block {match.indicator} at the firewall",
                            "Investigate affected systems",
                        ],
                    )
                )

            results.append(
                AnalysisResult(
                    analyzer_name="IOCChecker",
                    findings=ioc_findings,
                    iocs={"ips": [m.indicator for m in ioc_matches if m.indicator_type == "ip"]},
                )
            )

    duration = time.time() - start_time
    return pcap_data, results, duration


def main() -> int:
    """Main entry point."""
    args = parse_args()

    if not args.command:
        print("Error: No command specified. Use --help for usage information.")
        return 1

    # Load configuration
    config_path = getattr(args, "config", "config.yaml")
    try:
        if Path(config_path).exists():
            config = load_config(config_path)
        else:
            print(f"[!] Config file not found: {config_path}, using defaults")
            config = {}
    except Exception as e:
        print(f"[!] Error loading config: {e}, using defaults")
        config = {}

    # Setup logging
    log_config = config.get("logging", {})
    logger = setup_logger(
        level=log_config.get("level", "INFO") if not getattr(args, "verbose", False) else "DEBUG",
        log_file=log_config.get("file"),
    )

    if args.command == "info":
        # Quick info command
        from src.pcap_parser import get_pcap_info

        try:
            info = get_pcap_info(args.pcap_file)
            print(f"\nPCAP File Information:")
            print(f"  Path: {info['file_path']}")
            print(f"  Size: {info['file_size']:,} bytes")
            print(f"  Packets: {info['packet_count']:,}")
        except Exception as e:
            print(f"Error: {e}")
            return 1

    elif args.command == "analyze":
        # Full analysis
        pcap_path = args.pcap_file

        if not Path(pcap_path).exists():
            print(f"Error: PCAP file not found: {pcap_path}")
            return 1

        print("\n" + "=" * 60)
        print("  SOC PCAP Analyzer - Security Incident Analysis")
        print("=" * 60 + "\n")

        try:
            # Run analysis
            pcap_data, results, duration = run_analysis(
                pcap_path=pcap_path,
                config=config,
                quick_mode=args.quick,
                use_api=not args.no_api,
                verbose=args.verbose,
            )

            # Generate report
            print("[*] Generating report...")
            report_gen = ReportGenerator(config)
            report_data = report_gen.generate(pcap_data, results, duration)

            # Export report
            output_format = args.format.lower()
            if output_format == "md":
                output_format = "markdown"

            if args.output:
                output_path = args.output
            else:
                ext = "md" if output_format == "markdown" else output_format
                output_path = f"output/report_{report_data.report_id}.{ext}"

            # Ensure output directory exists
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

            template_dir = Path("src/reporting/templates")
            exporter = get_exporter(
                output_format,
                template_dir=str(template_dir) if template_dir.exists() else None,
            )
            exported_path = exporter.export(report_data, output_path)

            # Print summary
            print("\n" + "=" * 60)
            print("  Analysis Complete")
            print("=" * 60)
            print(f"\n  Risk Level: {report_data._get_risk_level()}")
            print(f"  Total Findings: {len(report_data.findings)}")
            print(f"    - Critical: {report_data.critical_count}")
            print(f"    - High: {report_data.high_count}")
            print(f"    - Medium: {report_data.medium_count}")
            print(f"    - Low: {report_data.low_count}")
            print(f"\n  Report saved to: {exported_path}")
            print(f"  Analysis duration: {duration:.2f} seconds\n")

            return 0

        except Exception as e:
            logger.exception("Analysis failed")
            print(f"\nError: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
