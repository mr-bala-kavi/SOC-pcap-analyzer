# SOC PCAP Analyzer

An automated SOC analyst tool for processing PCAP files and generating professional security incident reports.

## Features

- **PCAP Analysis**: Parse network captures using tshark with stream processing for large files
- **Attack Detection**: Identify port scans, brute force, C2 beaconing, data exfiltration, SQL injection, and more
- **Threat Intelligence**: Check indicators against local IOC database and external APIs (VirusTotal, AbuseIPDB)
- **MITRE ATT&CK Mapping**: Map findings to MITRE ATT&CK techniques and tactics
- **Professional Reports**: Generate reports in PDF, Markdown, or JSON format

## Installation

### Prerequisites

- Python 3.10+
- tshark (part of Wireshark)
- Kali Linux (recommended) or any Linux distribution

### Setup

```bash
# Clone or navigate to the project directory
cd soc-pcap-analyzer

# Install Python dependencies
pip3 install -r requirements.txt

# Verify tshark is installed
tshark --version
```

## Usage

### Basic Analysis

```bash
# Analyze a PCAP file (outputs Markdown report)
python main.py analyze capture.pcap

# Generate PDF report
python main.py analyze capture.pcap --format pdf --output report.pdf

# Quick scan mode (faster, skips deep analysis)
python main.py analyze capture.pcap --quick

# Verbose output
python main.py analyze capture.pcap -v
```

### Get PCAP Info

```bash
python main.py info capture.pcap
```

### Command Line Options

```
usage: main.py analyze [-h] [-o OUTPUT] [-f {pdf,markdown,md,json}]
                       [-c CONFIG] [-v] [--quick] [--no-api] pcap_file

positional arguments:
  pcap_file             Path to PCAP file to analyze

optional arguments:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output file path
  -f, --format          Output format: pdf, markdown, json (default: markdown)
  -c, --config CONFIG   Configuration file path (default: config.yaml)
  -v, --verbose         Enable verbose output
  --quick               Quick scan mode (skip deep analysis)
  --no-api              Disable external API lookups
```

## Configuration

Edit `config.yaml` to customize:

```yaml
analysis:
  max_packets: 0          # 0 = unlimited
  timeout_seconds: 300
  chunk_size: 10000

detection:
  port_scan_threshold: 20
  brute_force_threshold: 5
  beacon_interval_tolerance: 0.1

reporting:
  default_format: pdf
  include_raw_packets: false

threat_intel:
  virustotal:
    enabled: true
    api_key: "YOUR_API_KEY"
  abuseipdb:
    enabled: true
    api_key: "YOUR_API_KEY"
```

## Detection Capabilities

| Attack Type | Detection Method | MITRE ATT&CK |
|-------------|------------------|--------------|
| Port Scan | Multiple ports from single IP | T1046 |
| Brute Force | Repeated auth attempts | T1110 |
| C2 Beaconing | Regular interval connections | T1071 |
| Data Exfiltration | Large outbound transfers | T1048 |
| DNS Tunneling | Long DNS queries | T1071.004 |
| SQL Injection | Malicious patterns in HTTP | T1190 |
| Command Injection | Shell command patterns | T1059 |
| ARP Spoofing | Excessive ARP traffic | T1557.002 |
| DoS/DDoS | High traffic volume | T1498 |

## Report Sections

Generated reports include:

1. **Executive Summary** - High-level risk assessment
2. **Network Statistics** - Packet counts, duration, unique IPs
3. **Findings by Severity** - Critical, High, Medium, Low
4. **IOCs** - Suspicious IPs, domains, ports
5. **MITRE ATT&CK Coverage** - Mapped techniques
6. **Timeline** - Chronological events
7. **Recommendations** - Prioritized remediation steps

## Project Structure

```
soc-pcap-analyzer/
├── main.py                 # CLI entry point
├── config.yaml             # Configuration
├── requirements.txt        # Dependencies
├── src/
│   ├── pcap_parser.py      # PCAP parsing
│   ├── analyzers/          # Detection modules
│   │   ├── traffic_analyzer.py
│   │   ├── anomaly_detector.py
│   │   └── attack_detector.py
│   ├── threat_intel/       # Threat intelligence
│   │   ├── ioc_checker.py
│   │   ├── api_clients.py
│   │   └── mitre_mapper.py
│   ├── reporting/          # Report generation
│   │   ├── report_generator.py
│   │   └── exporters.py
│   └── utils/              # Utilities
├── rules/                  # Detection rules (YAML)
├── tests/                  # Unit tests
└── output/                 # Generated reports
```

## Extending the Tool

### Adding Custom Detection Rules

Edit `rules/attack_signatures.yaml`:

```yaml
my_custom_rule:
  description: "Detect custom attack pattern"
  enabled: true
  patterns:
    - "pattern1"
    - "pattern2"
  severity: high
  mitre_technique: T1234
```

### Adding IOCs

Edit `rules/ioc_lists.yaml`:

```yaml
malicious_ips:
  - ip: "1.2.3.4"
    category: "malware_c2"
    severity: "critical"
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_parser.py -v
```

## API Keys Setup

For threat intelligence lookups:

1. **VirusTotal**: Get free API key from https://www.virustotal.com/
2. **AbuseIPDB**: Get free API key from https://www.abuseipdb.com/

Add keys to `config.yaml` or use environment variables.

## Example Output

```
============================================================
  SOC PCAP Analyzer - Security Incident Analysis
============================================================

[*] Parsing PCAP file: capture.pcap
    Parsed 15432 packets, 234 connections
[*] Running traffic analysis...
[*] Running anomaly detection...
[*] Running attack detection...
[*] Checking IOCs...
[*] Generating report...

============================================================
  Analysis Complete
============================================================

  Risk Level: HIGH
  Total Findings: 12
    - Critical: 2
    - High: 5
    - Medium: 3
    - Low: 2

  Report saved to: output/report_ABC123.md
  Analysis duration: 4.23 seconds
```

## License

MIT License

## Contributing

Contributions welcome! Please submit issues and pull requests.
