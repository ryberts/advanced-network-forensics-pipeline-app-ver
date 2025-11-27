#!/usr/bin/env python3
"""
Report generator
"""
import json
import os
from datetime import datetime
import logging
import matplotlib.pyplot as plt

class ReportGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate(self, packet_data, threats, output_dir):
        report_dir = os.path.join(output_dir, 'forensics_report')
        os.makedirs(report_dir, exist_ok=True)
        self._generate_json_report(packet_data, threats, report_dir)
        self._generate_html_report(packet_data, threats, report_dir)
        self._generate_executive_summary(packet_data, threats, report_dir)
        self._generate_visualizations(packet_data, threats, report_dir)
        self.logger.info(f"Reports generated in: {report_dir}")
        return report_dir

    def _generate_json_report(self, packet_data, threats, report_dir):
        report_data = {
            'metadata': {'generated_at': datetime.now().isoformat(), 'analysis_version': '1.0'},
            'statistics': {'total_packets': packet_data.get('total_packets', 0), 'protocols': dict(packet_data.get('protocols', {})), 'conversations': dict(packet_data.get('conversations', {})), 'ports': dict(packet_data.get('ports', {}))},
            'threats': threats,
            'findings': {'dns_queries': len(packet_data.get('dns_queries', [])), 'http_requests': len(packet_data.get('http_requests', []))}
        }
        with open(f"{report_dir}/detailed_analysis.json", 'w') as f:
            json.dump(report_data, f, indent=2)

    def _generate_html_report(self, packet_data, threats, report_dir):
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'>
  <title>Network Forensics Report</title>
</head>
<body>
  <h1>Network Forensics Analysis Report</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
  <h2>Executive Summary</h2>
  <p>Total Packets Analyzed: {packet_data.get('total_packets',0)}</p>
  <p>Threats Detected: {threats.get('summary', {}).get('total',0)}</p>
</body>
</html>
"""
        with open(f"{report_dir}/forensics_report.html", 'w') as f:
            f.write(html_content)

    def _generate_executive_summary(self, packet_data, threats, report_dir):
        summary = f"NETWORK FORENSICS ANALYSIS - EXECUTIVE SUMMARY\n\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nKEY FINDINGS:\n- Total Packets Analyzed: {packet_data.get('total_packets',0)}\n- Security Threats Detected: {threats.get('summary', {}).get('total',0)}\n"
        with open(f"{report_dir}/executive_summary.txt", 'w') as f:
            f.write(summary)

    def _generate_visualizations(self, packet_data, threats, report_dir):
        try:
            if packet_data.get('protocols'):
                plt.figure(figsize=(10, 6))
                protocols = list(packet_data['protocols'].keys())
                counts = list(packet_data['protocols'].values())
                plt.bar(protocols, counts)
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(f"{report_dir}/protocols.png", dpi=150, bbox_inches='tight')
                plt.close()
        except Exception as e:
            self.logger.warning(f"Visualization generation failed: {str(e)}")