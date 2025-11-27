#!/usr/bin/env python3
"""
Threat Detection Engine
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
        self.logger.info("Running threat detection...")
        threats = {
            'high_severity': [],
            'medium_severity': [],
            'low_severity': [],
            'summary': {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        }

        self._detect_port_scans(packet_data, threats)
        self._detect_suspicious_ports(packet_data, threats)
        self._detect_data_exfiltration(packet_data, threats)
        self._detect_dns_anomalies(packet_data, threats)

        threats['summary'] = {
            'total': len(threats['high_severity']) + len(threats['medium_severity']) + len(threats['low_severity']),
            'high': len(threats['high_severity']),
            'medium': len(threats['medium_severity']),
            'low': len(threats['low_severity'])
        }
        return threats

    def _detect_port_scans(self, packet_data, threats):
        src_ports = defaultdict(set)
        for conversation in packet_data.get('conversations', {}):
            if ' -> ' in conversation:
                src_ip, dst_ip = conversation.split(' -> ')
                if ':' in dst_ip:
                    dst_ip, port = dst_ip.split(':')
                    src_ports[src_ip].add(port)
        for src_ip, ports in src_ports.items():
            if len(ports) > 10:
                threats['medium_severity'].append({'type': 'Port Scan', 'source_ip': src_ip, 'ports_targeted': len(ports), 'description': f'Potential port scan from {src_ip} to {len(ports)} different ports', 'confidence': 'Medium'})

    def _detect_suspicious_ports(self, packet_data, threats):
        for port_proto, count in packet_data.get('ports', {}).items():
            protocol, port_str = port_proto.split('/')
            try:
                port = int(port_str)
            except ValueError:
                continue
            if protocol == 'tcp' and port in self.suspicious_ports['tcp']:
                threats['high_severity'].append({'type': 'Suspicious Port', 'port': port_proto, 'count': count, 'description': f'Communication on known suspicious port {port_proto}', 'confidence': 'High'})

    def _detect_data_exfiltration(self, packet_data, threats):
        if packet_data.get('total_packets', 0) > 1000:
            threats['low_severity'].append({'type': 'Potential Data Exfiltration', 'packet_count': packet_data.get('total_packets', 0), 'description': 'High packet volume detected - review for data exfiltration', 'confidence': 'Low'})

    def _detect_dns_anomalies(self, packet_data, threats):
        if len(packet_data.get('dns_queries', [])) > 50:
            threats['medium_severity'].append({'type': 'DNS Anomaly', 'query_count': len(packet_data.get('dns_queries', [])), 'description': 'High volume of DNS queries detected', 'confidence': 'Medium'})