#!/usr/bin/env python3
"""
Threat Detection Engine
Multi-stage attack pattern recognition
"""

import logging
from collections import defaultdict

class ThreatDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_ports = {
            'tcp': [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321],
            'udp': [69, 161, 162, 1434, 1900, 5353]
        }
    
    def analyze(self, packet_data):
        """Detect security threats in network traffic"""
        self.logger.info("Running threat detection...")
        
        threats = {
            'high_severity': [],
            'medium_severity': [],
            'low_severity': [],
            'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        # Detect port scanning
        self._detect_port_scans(packet_data, threats)
        
        # Detect suspicious ports
        self._detect_suspicious_ports(packet_data, threats)
        
        # Detect data exfiltration
        self._detect_data_exfiltration(packet_data, threats)
        
        # Detect DNS anomalies
        self._detect_dns_anomalies(packet_data, threats)
        
        # Update summary
        threats['summary'] = {
            'total': len(threats['high_severity']) + len(threats['medium_severity']) + len(threats['low_severity']),
            'high': len(threats['high_severity']),
            'medium': len(threats['medium_severity']),
            'low': len(threats['low_severity'])
        }
        
        return threats
    
    def _detect_port_scans(self, packet_data, threats):
        """Detect potential port scanning activity"""
        src_ports = defaultdict(set)
        
        for conversation in packet_data['conversations']:
            if ' -> ' in conversation:
                src_ip, dst_ip = conversation.split(' -> ')
                # Extract port from conversation if available
                if ':' in dst_ip:
                    dst_ip, port = dst_ip.split(':')
                    src_ports[src_ip].add(port)
        
        for src_ip, ports in src_ports.items():
            if len(ports) > 10:  # Threshold for port scan
                threats['medium_severity'].append({
                    'type': 'Port Scan',
                    'source_ip': src_ip,
                    'ports_targeted': len(ports),
                    'description': f'Potential port scan from {src_ip} to {len(ports)} different ports',
                    'confidence': 'Medium'
                })
    
    def _detect_suspicious_ports(self, packet_data, threats):
        """Detect communication on known suspicious ports"""
        for port_proto, count in packet_data['ports'].items():
            protocol, port_str = port_proto.split('/')
            port = int(port_str)
            
            if protocol == 'tcp' and port in self.suspicious_ports['tcp']:
                threats['high_severity'].append({
                    'type': 'Suspicious Port',
                    'port': port_proto,
                    'count': count,
                    'description': f'Communication on known suspicious port {port_proto}',
                    'confidence': 'High'
                })
    
    def _detect_data_exfiltration(self, packet_data, threats):
        """Detect potential data exfiltration"""
        # Simple heuristic: high volume to external IPs
        if packet_data['total_packets'] > 1000:
            threats['low_severity'].append({
                'type': 'Potential Data Exfiltration',
                'packet_count': packet_data['total_packets'],
                'description': 'High packet volume detected - review for data exfiltration',
                'confidence': 'Low'
            })
    
    def _detect_dns_anomalies(self, packet_data, threats):
        """Detect DNS-based threats"""
        if len(packet_data['dns_queries']) > 50:
            threats['medium_severity'].append({
                'type': 'DNS Anomaly',
                'query_count': len(packet_data['dns_queries']),
                'description': 'High volume of DNS queries detected',
                'confidence': 'Medium'
            })