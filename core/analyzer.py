#!/usr/bin/env python3
"""
Packet Analysis Engine
"""
from scapy.all import rdpcap
import logging
from collections import Counter

class PacketAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, pcap_file, max_packets=50000):
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

        packets = rdpcap(pcap_file)
        self.logger.info(f"Loaded {len(packets)} packets from file")

        for idx, packet in enumerate(packets):
            if idx >= max_packets:
                break
            try:
                analysis['total_packets'] += 1

                if packet.haslayer('IP'):
                    ip_layer = packet['IP']
                    src_ip = getattr(ip_layer, 'src', None)
                    dst_ip = getattr(ip_layer, 'dst', None)
                    proto = getattr(ip_layer, 'proto', None)

                    conv = f"{src_ip} -> {dst_ip}"
                    analysis['conversations'][conv] += 1

                    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 41: 'IPv6'}
                    proto_name = proto_map.get(proto, f"Other({proto})")
                    analysis['protocols'][proto_name] += 1

                    if packet.haslayer('TCP'):
                        tcp_layer = packet['TCP']
                        dst_port = getattr(tcp_layer, 'dport', None)
                        analysis['ports'][f"tcp/{dst_port}"] += 1
                    elif packet.haslayer('UDP'):
                        udp_layer = packet['UDP']
                        dst_port = getattr(udp_layer, 'dport', None)
                        analysis['ports'][f"udp/{dst_port}"] += 1

                    if packet.haslayer('Raw'):
                        try:
                            payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                            if 'GET ' in payload or 'POST ' in payload or 'HTTP' in payload:
                                if 'Host:' in payload:
                                    host_line = [line for line in payload.split('\n') if 'Host:' in line]
                                    if host_line:
                                        host = host_line[0].split('Host: ')[1].strip()
                                        analysis['http_requests'].append({'method': 'GET' if 'GET' in payload else 'POST', 'uri': payload.split('\n')[0], 'host': host})
                        except Exception:
                            pass

            except Exception as e:
                self.logger.debug(f"Packet {idx} processing error: {str(e)}")
                continue

        self.logger.info(f"Successfully analyzed {analysis['total_packets']} packets")
        return analysis