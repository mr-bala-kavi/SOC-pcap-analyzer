"""Report export modules for PDF, Markdown, and JSON formats."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..utils.logger import get_logger
from .report_generator import ReportData, create_executive_summary

logger = get_logger(__name__)


class BaseExporter(ABC):
    """Abstract base class for report exporters."""

    @abstractmethod
    def export(self, report_data: ReportData, output_path: str) -> str:
        """
        Export report to file.

        Args:
            report_data: Report data to export
            output_path: Output file path

        Returns:
            Path to exported file
        """
        pass


class MarkdownExporter(BaseExporter):
    """Export reports to Markdown format."""

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize Markdown exporter.

        Args:
            template_dir: Directory containing Jinja2 templates
        """
        if template_dir:
            self.env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            self.env = None

    def export(self, report_data: ReportData, output_path: str) -> str:
        """Export report to Markdown file."""
        logger.info(f"Exporting report to Markdown: {output_path}")

        # Use template if available, otherwise generate directly
        if self.env and "report.md.j2" in self.env.list_templates():
            template = self.env.get_template("report.md.j2")
            content = template.render(**report_data.to_dict())
        else:
            content = self._generate_markdown(report_data)

        # Write to file
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

        logger.info(f"Markdown report exported: {output_path}")
        return str(path.absolute())

    def _generate_markdown(self, report_data: ReportData) -> str:
        """Generate Markdown content directly."""
        data = report_data.to_dict()
        lines = []

        # Header
        lines.append(f"# Security Incident Report")
        lines.append(f"\n**Report ID:** {data['report_id']}")
        lines.append(f"**Generated:** {data['generated_at']}")
        lines.append(f"**PCAP File:** {data['pcap_file']}")
        lines.append(f"**Risk Level:** {data['risk_level']} (Score: {data['risk_score']}/100)")

        # Executive Summary
        lines.append("\n## Executive Summary\n")
        lines.append(create_executive_summary(report_data))

        # Overview Statistics
        lines.append("\n## Overview Statistics\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Packets | {data['total_packets']:,} |")
        lines.append(f"| Total Bytes | {data['total_bytes_formatted']} |")
        lines.append(f"| Capture Duration | {data['capture_duration']} seconds |")
        lines.append(f"| Unique IPs | {data['unique_ips']} |")
        lines.append(f"| Unique Ports | {data['unique_ports']} |")
        lines.append(f"| Analysis Duration | {data['analysis_duration']} seconds |")

        # Findings Summary
        lines.append("\n## Findings Summary\n")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        lines.append(f"| Critical | {data['critical_count']} |")
        lines.append(f"| High | {data['high_count']} |")
        lines.append(f"| Medium | {data['medium_count']} |")
        lines.append(f"| Low | {data['low_count']} |")
        lines.append(f"| **Total** | **{data['total_findings']}** |")

        # Detailed Findings
        if data['findings']:
            lines.append("\n## Detailed Findings\n")

            for severity in ["critical", "high", "medium", "low"]:
                findings = data['findings_by_severity'].get(severity, [])
                if findings:
                    lines.append(f"\n### {severity.upper()} Severity\n")
                    for i, finding in enumerate(findings, 1):
                        lines.append(f"#### {i}. {finding['title']}\n")
                        lines.append(f"**Category:** {finding['category']}")
                        if finding.get('mitre_technique'):
                            lines.append(f"**MITRE ATT&CK:** {finding['mitre_technique']}")
                        lines.append(f"\n{finding['description']}\n")

                        if finding.get('source_ip'):
                            lines.append(f"- **Source IP:** {finding['source_ip']}")
                        if finding.get('destination_ip'):
                            lines.append(f"- **Destination IP:** {finding['destination_ip']}")
                        if finding.get('destination_port'):
                            lines.append(f"- **Port:** {finding['destination_port']}")

                        if finding.get('evidence'):
                            lines.append("\n**Evidence:**")
                            for ev in finding['evidence']:
                                lines.append(f"- {ev}")

                        if finding.get('recommendations'):
                            lines.append("\n**Recommendations:**")
                            for rec in finding['recommendations']:
                                lines.append(f"- {rec}")

                        lines.append("")

        # IOCs
        lines.append("\n## Indicators of Compromise (IOCs)\n")

        if data['malicious_ips']:
            lines.append("\n### Suspicious IP Addresses\n")
            lines.append("```")
            for ip in data['malicious_ips'][:20]:
                lines.append(ip)
            if len(data['malicious_ips']) > 20:
                lines.append(f"... and {len(data['malicious_ips']) - 20} more")
            lines.append("```")

        if data['malicious_domains']:
            lines.append("\n### Suspicious Domains\n")
            lines.append("```")
            for domain in data['malicious_domains'][:20]:
                lines.append(domain)
            if len(data['malicious_domains']) > 20:
                lines.append(f"... and {len(data['malicious_domains']) - 20} more")
            lines.append("```")

        if data['suspicious_ports']:
            lines.append("\n### Suspicious Ports\n")
            lines.append(", ".join(str(p) for p in data['suspicious_ports']))

        # MITRE ATT&CK Coverage
        if data['mitre_coverage']:
            lines.append("\n## MITRE ATT&CK Coverage\n")
            for tactic, techniques in data['mitre_coverage'].items():
                lines.append(f"\n### {tactic}\n")
                for tech in techniques:
                    lines.append(f"- **{tech['technique_id']}**: {tech['name']}")

        # Timeline
        if data['timeline']:
            lines.append("\n## Event Timeline\n")
            lines.append("| Time | Event | Severity | Details |")
            lines.append("|------|-------|----------|---------|")
            for event in data['timeline'][:50]:
                lines.append(
                    f"| {event.get('time_formatted', 'N/A')} | "
                    f"{event.get('title', 'Unknown')} | "
                    f"{event.get('severity', 'N/A')} | "
                    f"{event.get('source_ip', '')} -> {event.get('destination_ip', '')} |"
                )

        # Recommendations
        if data['recommendations']:
            lines.append("\n## Recommendations\n")
            for i, rec in enumerate(data['recommendations'], 1):
                lines.append(f"{i}. {rec}")

        # Footer
        lines.append("\n---")
        lines.append("\n*Generated by SOC PCAP Analyzer*")

        return "\n".join(lines)


class JSONExporter(BaseExporter):
    """Export reports to JSON format."""

    def __init__(self, indent: int = 2):
        """
        Initialize JSON exporter.

        Args:
            indent: JSON indentation level
        """
        self.indent = indent

    def export(self, report_data: ReportData, output_path: str) -> str:
        """Export report to JSON file."""
        logger.info(f"Exporting report to JSON: {output_path}")

        data = report_data.to_dict()

        # Write to file
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(data, f, indent=self.indent, default=str)

        logger.info(f"JSON report exported: {output_path}")
        return str(path.absolute())


class PDFExporter(BaseExporter):
    """Export reports to PDF format using weasyprint."""

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize PDF exporter.

        Args:
            template_dir: Directory containing Jinja2 templates
        """
        if template_dir:
            self.env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            self.env = None

    def export(self, report_data: ReportData, output_path: str) -> str:
        """Export report to PDF file."""
        logger.info(f"Exporting report to PDF: {output_path}")

        try:
            from weasyprint import HTML
        except ImportError:
            logger.error("weasyprint not installed. Falling back to Markdown.")
            md_exporter = MarkdownExporter()
            return md_exporter.export(report_data, output_path.replace(".pdf", ".md"))

        # Generate HTML
        if self.env and "report.html" in self.env.list_templates():
            template = self.env.get_template("report.html")
            html_content = template.render(**report_data.to_dict())
        else:
            html_content = self._generate_html(report_data)

        # Convert to PDF
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        HTML(string=html_content).write_pdf(str(path))

        logger.info(f"PDF report exported: {output_path}")
        return str(path.absolute())

    def _generate_html(self, report_data: ReportData) -> str:
        """Generate HTML content for PDF."""
        data = report_data.to_dict()

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Incident Report - {data['report_id']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
            margin: 40px;
        }}
        h1 {{
            color: #1a1a2e;
            border-bottom: 3px solid #e94560;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #16213e;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        h3 {{
            color: #0f3460;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 20px;
            margin: -40px -40px 30px -40px;
        }}
        .header h1 {{
            color: white;
            border: none;
            margin: 0;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 10px;
        }}
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-medium {{ background: #ffc107; color: black; }}
        .risk-low {{ background: #28a745; color: white; }}
        .risk-none {{ background: #6c757d; color: white; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background: #f8f9fa;
            font-weight: bold;
        }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }}
        .finding-critical {{ border-left: 5px solid #dc3545; }}
        .finding-high {{ border-left: 5px solid #fd7e14; }}
        .finding-medium {{ border-left: 5px solid #ffc107; }}
        .finding-low {{ border-left: 5px solid #28a745; }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 10pt;
            font-weight: bold;
        }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #28a745; color: white; }}
        code {{
            background: #f4f4f4;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }}
        pre {{
            background: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .summary-box {{
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 24pt;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .stat-label {{
            font-size: 10pt;
            color: #666;
        }}
        .page-break {{
            page-break-before: always;
        }}
        footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 9pt;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Incident Report</h1>
        <div>Report ID: {data['report_id']}</div>
        <div>Generated: {data['generated_at']}</div>
        <span class="risk-badge risk-{data['risk_level'].lower()}">{data['risk_level']} RISK</span>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-box">
        <p><strong>PCAP File:</strong> {data['pcap_file']}</p>
        <p><strong>Analysis Duration:</strong> {data['analysis_duration']} seconds</p>
        <p><strong>Risk Score:</strong> {data['risk_score']}/100</p>
        <p>Analysis identified <strong>{data['total_findings']} security findings</strong> across
           {data['total_packets']:,} packets ({data['total_bytes_formatted']}).</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{data['critical_count']}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{data['high_count']}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{data['medium_count']}</div>
            <div class="stat-label">Medium</div>
        </div>
    </div>

    <h2>Network Statistics</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Packets</td><td>{data['total_packets']:,}</td></tr>
        <tr><td>Total Bytes</td><td>{data['total_bytes_formatted']}</td></tr>
        <tr><td>Capture Duration</td><td>{data['capture_duration']} seconds</td></tr>
        <tr><td>Unique IPs</td><td>{data['unique_ips']}</td></tr>
        <tr><td>Unique Ports</td><td>{data['unique_ports']}</td></tr>
    </table>
"""

        # Add findings
        if data['findings']:
            html += '<h2 class="page-break">Security Findings</h2>'

            for severity in ["critical", "high", "medium", "low"]:
                findings = data['findings_by_severity'].get(severity, [])
                if findings:
                    html += f'<h3>{severity.upper()} Severity ({len(findings)})</h3>'
                    for finding in findings:
                        html += f'''
    <div class="finding finding-{severity}">
        <h4>{finding['title']} <span class="severity-badge severity-{severity}">{severity.upper()}</span></h4>
        <p><strong>Category:</strong> {finding['category']}</p>
        {"<p><strong>MITRE ATT&CK:</strong> " + finding['mitre_technique'] + "</p>" if finding.get('mitre_technique') else ""}
        <p>{finding['description']}</p>
        {"<p><strong>Source IP:</strong> " + str(finding['source_ip']) + "</p>" if finding.get('source_ip') else ""}
        {"<p><strong>Destination:</strong> " + str(finding.get('destination_ip', '')) + ":" + str(finding.get('destination_port', '')) + "</p>" if finding.get('destination_ip') else ""}
    </div>
'''

        # Add IOCs
        html += '<h2 class="page-break">Indicators of Compromise</h2>'

        if data['malicious_ips']:
            html += '<h3>Suspicious IP Addresses</h3><pre>'
            html += '\n'.join(data['malicious_ips'][:30])
            if len(data['malicious_ips']) > 30:
                html += f'\n... and {len(data["malicious_ips"]) - 30} more'
            html += '</pre>'

        if data['malicious_domains']:
            html += '<h3>Suspicious Domains</h3><pre>'
            html += '\n'.join(data['malicious_domains'][:30])
            if len(data['malicious_domains']) > 30:
                html += f'\n... and {len(data["malicious_domains"]) - 30} more'
            html += '</pre>'

        # Add recommendations
        if data['recommendations']:
            html += '<h2>Recommendations</h2><ol>'
            for rec in data['recommendations'][:15]:
                html += f'<li>{rec}</li>'
            html += '</ol>'

        html += '''
    <footer>
        Generated by SOC PCAP Analyzer
    </footer>
</body>
</html>
'''
        return html


def get_exporter(format_type: str, template_dir: Optional[str] = None) -> BaseExporter:
    """
    Get appropriate exporter for format type.

    Args:
        format_type: Export format (pdf, markdown, json)
        template_dir: Optional template directory

    Returns:
        Appropriate exporter instance
    """
    format_type = format_type.lower()

    if format_type == "pdf":
        return PDFExporter(template_dir)
    elif format_type in ["markdown", "md"]:
        return MarkdownExporter(template_dir)
    elif format_type == "json":
        return JSONExporter()
    else:
        raise ValueError(f"Unsupported export format: {format_type}")
