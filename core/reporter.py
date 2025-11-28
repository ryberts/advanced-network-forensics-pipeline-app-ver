#!/usr/bin/env python3
"""
Professional Report Generator
HTML, JSON, and executive summary reports
"""

import json
import os
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import logging

class ReportGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate(self, packet_data, threats, output_dir):
        """Generate comprehensive forensics reports"""
        self.logger.info("Generating reports...")
        
        # Create report directory
        report_dir = f"{output_dir}/forensics_report"
        os.makedirs(report_dir, exist_ok=True)
        
        # Generate JSON report
        self._generate_json_report(packet_data, threats, report_dir)
        
        # Generate HTML report
        self._generate_html_report(packet_data, threats, report_dir)
        
        # Generate executive summary
        self._generate_executive_summary(packet_data, threats, report_dir)
        
        # Generate visualizations
        self._generate_visualizations(packet_data, threats, report_dir)
        
        self.logger.info(f"Reports generated in: {report_dir}")
        return report_dir
    
    def _generate_json_report(self, packet_data, threats, report_dir):
        """Generate detailed JSON report"""
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'analysis_version': '1.0'
            },
            'statistics': {
                'total_packets': packet_data['total_packets'],
                'protocols': dict(packet_data['protocols']),
                'conversations': dict(packet_data['conversations']),
                'ports': dict(packet_data['ports'])
            },
            'threats': threats,
            'findings': {
                'dns_queries': len(packet_data['dns_queries']),
                'http_requests': len(packet_data['http_requests'])
            }
        }
        
        with open(f"{report_dir}/detailed_analysis.json", 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def _generate_html_report(self, packet_data, threats, report_dir):
        """Generate professional HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Forensics Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
        .critical {{ border-left-color: #e74c3c; background: #fdf2f2; }}
        .high {{ border-left-color: #f39c12; background: #fef9e7; }}
        .medium {{ border-left-color: #f1c40f; background: #fffbf0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Forensics Analysis Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p><strong>Total Packets Analyzed:</strong> {packet_data['total_packets']:,}</p>
        <p><strong>Threats Detected:</strong> {threats['summary']['total']}</p>
        <p><strong>Risk Level:</strong> {'HIGH' if threats['summary']['high'] > 0 else 'MEDIUM' if threats['summary']['medium'] > 0 else 'LOW'}</p>
    </div>
    
    <div class="section">
        <h2>Threat Summary</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>High</td><td>{threats['summary']['high']}</td></tr>
            <tr><td>Medium</td><td>{threats['summary']['medium']}</td></tr>
            <tr><td>Low</td><td>{threats['summary']['low']}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Network Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Protocols</td><td>{len(packet_data['protocols'])}</td></tr>
            <tr><td>Conversations</td><td>{len(packet_data['conversations'])}</td></tr>
            <tr><td>DNS Queries</td><td>{len(packet_data['dns_queries'])}</td></tr>
            <tr><td>HTTP Requests</td><td>{len(packet_data['http_requests'])}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Detailed Findings</h2>
        <h3>Top Protocols</h3>
        <ul>
            {"".join(f"<li>{proto}: {count}</li>" for proto, count in packet_data['protocols'].most_common(5))}
        </ul>
        
        <h3>Security Alerts</h3>
        {"".join(self._format_threat_html(threat) for threat in threats['high_severity'] + threats['medium_severity'])}
    </div>
</body>
</html>
        """
        
        with open(f"{report_dir}/forensics_report.html", 'w') as f:
            f.write(html_content)
    
    def _format_threat_html(self, threat):
        """Format individual threat for HTML report"""
        severity_class = threat['confidence'].lower()
        return f"""
        <div class="section {severity_class}">
            <h4>{threat['type']} - {threat['confidence']} Severity</h4>
            <p>{threat['description']}</p>
        </div>
        """
    
    def _generate_executive_summary(self, packet_data, threats, report_dir):
        """Generate executive summary for management"""
        summary = f"""
NETWORK FORENSICS ANALYSIS - EXECUTIVE SUMMARY
=============================================

Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Analysis Scope: Complete network traffic analysis

KEY FINDINGS:
- Total Packets Analyzed: {packet_data['total_packets']:,}
- Security Threats Detected: {threats['summary']['total']}
- High Severity Threats: {threats['summary']['high']}
- Medium Severity Threats: {threats['summary']['medium']}

RISK ASSESSMENT: {'HIGH' if threats['summary']['high'] > 0 else 'MEDIUM' if threats['summary']['medium'] > 0 else 'LOW'}

RECOMMENDATIONS:
1. Review high severity threats immediately
2. Monitor suspicious IP addresses
3. Consider network segmentation if lateral movement detected
4. Update security controls based on findings

Generated by: Advanced Network Forensics Pipeline v1.0
        """
        
        with open(f"{report_dir}/executive_summary.txt", 'w') as f:
            f.write(summary)
    
    def _generate_visualizations(self, packet_data, threats, report_dir):
        """Generate analysis visualizations"""
        try:
            plt.style.use('seaborn')
            
            # Protocol distribution
            if packet_data['protocols']:
                plt.figure(figsize=(10, 6))
                protocols = list(packet_data['protocols'].keys())
                counts = list(packet_data['protocols'].values())
                plt.bar(protocols, counts)
                plt.title('Protocol Distribution')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(f"{report_dir}/protocols.png", dpi=150, bbox_inches='tight')
                plt.close()
            
            # Threat distribution
            if threats['summary']['total'] > 0:
                plt.figure(figsize=(8, 8))
                labels = ['High', 'Medium', 'Low']
                sizes = [threats['summary']['high'], threats['summary']['medium'], threats['summary']['low']]
                colors = ['#e74c3c', '#f39c12', '#27ae60']
                plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
                plt.title('Threat Severity Distribution')
                plt.savefig(f"{report_dir}/threats.png", dpi=150, bbox_inches='tight')
                plt.close()
                
        except Exception as e:
            self.logger.warning(f"Visualization generation failed: {str(e)}")