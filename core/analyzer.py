#!/usr/bin/env python3
"""
Packet Analysis Engine
Robust PCAP parsing and analysis (Windows compatible with Scapy)
"""

from scapy.all import rdpcap
import logging
from collections import Counter
import os

class PacketAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze(self, pcap_file, max_packets=50000):
        """Analyze PCAP file and extract key metrics"""
        self.logger.info(f"Analyzing {pcap_file}...")
        
        analysis = {
            'total_packets': 0,
            'protocols': Counter(),
            'conversations': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'timestamps': [],
            'dns_queries': [],
            'http_requests': [],
            'suspicious_activity': []
        }
        
        try:
            # Read PCAP file using Scapy
            packets = rdpcap(pcap_file)
            self.logger.info(f"Loaded {len(packets)} packets from file")
            
            for idx, packet in enumerate(packets):
                if idx >= max_packets:
                    break
                
                try:
                    analysis['total_packets'] += 1
                    
                    # IP Layer analysis
                    if packet.haslayer('IP'):
                        ip_layer = packet['IP']
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        proto = ip_layer.proto
                        
                        # Track conversations
                        conv = f"{src_ip} -> {dst_ip}"
                        analysis['conversations'][conv] += 1
                        
                        # Protocol tracking
                        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 41: 'IPv6'}
                        proto_name = proto_map.get(proto, f"Other({proto})")
                        analysis['protocols'][proto_name] += 1
                        
                        # TCP Port analysis
                        if packet.haslayer('TCP'):
                            tcp_layer = packet['TCP']
                            dst_port = tcp_layer.dport
                            analysis['ports'][f"tcp/{dst_port}"] += 1
                        
                        # UDP Port analysis
                        elif packet.haslayer('UDP'):
                            udp_layer = packet['UDP']
                            dst_port = udp_layer.dport
                            analysis['ports'][f"udp/{dst_port}"] += 1
                            
                            # DNS detection (port 53)
                            if dst_port == 53 and packet.haslayer('DNS'):
                                try:
                                    dns_layer = packet['DNS']
                                    if hasattr(dns_layer, 'qd') and dns_layer.qd:
                                        query = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                                        analysis['dns_queries'].append({
                                            'query': query,
                                            'src_ip': src_ip
                                        })
                                except:
                                    pass
                        
                        # HTTP detection
                        if packet.haslayer('Raw'):
                            try:
                                payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                                if 'GET ' in payload or 'POST ' in payload or 'HTTP' in payload:
                                    # Extract basic HTTP info
                                    if 'Host:' in payload:
                                        host_line = [line for line in payload.split('\n') if 'Host:' in line]
                                        if host_line:
                                            host = host_line[0].split('Host: ')[1].strip()
                                            analysis['http_requests'].append({
                                                'method': 'GET' if 'GET' in payload else 'POST',
                                                'uri': payload.split('\n')[0],
                                                'host': host
                                            })
                            except:
                                pass
                
                except Exception as e:
                    self.logger.debug(f"Packet {idx} processing error: {str(e)}")
                    continue
            
            self.logger.info(f"Successfully analyzed {analysis['total_packets']} packets")
            
            if analysis['total_packets'] == 0:
                self.logger.warning("No packets were analyzed from the PCAP file")
            
        except Exception as e:
            self.logger.error(f"Analysis error: {str(e)}")
            raise
        
        return analysis