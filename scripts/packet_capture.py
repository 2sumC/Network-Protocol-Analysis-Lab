"""
Real-Time Packet Capture & Analysis Script
==========================================

Uses Scapy to capture and analyze network packets in real-time.
Supports filtering by protocol and automatic analysis.

Requirements:
    pip install scapy

Usage:
    sudo python packet_capture.py              # Capture all packets
    sudo python packet_capture.py --count 100  # Capture 100 packets
    sudo python packet_capture.py --filter tcp # Capture only TCP
    sudo python packet_capture.py --save      # Save to PCAP file
"""

from scapy.all import *
from datetime import datetime
import argparse
import json
from collections import defaultdict, Counter


class PacketAnalyzer:
    """Real-time packet capture and analysis"""
    
    def __init__(self):
        self.packets = []
        self.stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'tcp_flags': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'start_time': None,
            'end_time': None
        }
        self.tcp_connections = defaultdict(list)
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packets.append(packet)
        self.stats['total_packets'] += 1
        
        # Record time
        if self.stats['start_time'] is None:
            self.stats['start_time'] = datetime.now()
        self.stats['end_time'] = datetime.now()
        
        # Analyze packet
        self._analyze_packet(packet)
        
        # Print summary
        self._print_packet_summary(packet)
        
    def _analyze_packet(self, packet):
        """Extract packet information"""
        
        # Packet size
        self.stats['packet_sizes'].append(len(packet))
        
        # Protocol detection
        if packet.haslayer(TCP):
            self.stats['protocols']['TCP'] += 1
            self._analyze_tcp(packet)
        elif packet.haslayer(UDP):
            self.stats['protocols']['UDP'] += 1
            self._analyze_udp(packet)
        elif packet.haslayer(ICMP):
            self.stats['protocols']['ICMP'] += 1
        elif packet.haslayer(ARP):
            self.stats['protocols']['ARP'] += 1
        elif packet.haslayer(DNS):
            self.stats['protocols']['DNS'] += 1
        
        # IP layer analysis
        if packet.haslayer(IP):
            self.stats['src_ips'][packet[IP].src] += 1
            self.stats['dst_ips'][packet[IP].dst] += 1
            
    def _analyze_tcp(self, packet):
        """Analyze TCP packets"""
        tcp = packet[TCP]
        
        # Record ports
        self.stats['ports'][tcp.sport] += 1
        self.stats['ports'][tcp.dport] += 1
        
        # TCP flags
        flags = []
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.P: flags.append('PSH')
        
        flag_str = '+'.join(flags) if flags else 'NONE'
        self.stats['tcp_flags'][flag_str] += 1
        
        # Track TCP connections (3-way handshake)
        if packet.haslayer(IP):
            connection_key = f"{packet[IP].src}:{tcp.sport} -> {packet[IP].dst}:{tcp.dport}"
            self.tcp_connections[connection_key].append({
                'flags': flag_str,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'time': datetime.now()
            })
            
    def _analyze_udp(self, packet):
        """Analyze UDP packets"""
        udp = packet[UDP]
        self.stats['ports'][udp.sport] += 1
        self.stats['ports'][udp.dport] += 1
        
    def _print_packet_summary(self, packet):
        """Print packet summary to console"""
        summary_parts = []
        
        # Timestamp
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        summary_parts.append(f"[{timestamp}]")
        
        # Protocol and basic info
        if packet.haslayer(IP):
            ip = packet[IP]
            summary_parts.append(f"{ip.src:15s} -> {ip.dst:15s}")
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                flags = self._get_tcp_flags_str(tcp)
                summary_parts.append(f"TCP {tcp.sport} -> {tcp.dport} [{flags}]")
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                summary_parts.append(f"UDP {udp.sport} -> {udp.dport}")
                
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                summary_parts.append(f"ICMP type={icmp.type}")
                
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            summary_parts.append(f"ARP {arp.psrc} -> {arp.pdst}")
            
        # Length
        summary_parts.append(f"Len={len(packet)}")
        
        print(" ".join(summary_parts))
        
    def _get_tcp_flags_str(self, tcp):
        """Get TCP flags as string"""
        flags = []
        if tcp.flags.S: flags.append('S')
        if tcp.flags.A: flags.append('A')
        if tcp.flags.F: flags.append('F')
        if tcp.flags.R: flags.append('R')
        if tcp.flags.P: flags.append('P')
        return ''.join(flags) if flags else '-'
        
    def detect_tcp_handshakes(self):
        """Detect TCP 3-way handshakes"""
        handshakes = []
        
        for connection, packets in self.tcp_connections.items():
            if len(packets) >= 3:
                # Look for SYN, SYN+ACK, ACK pattern
                flags = [p['flags'] for p in packets[:3]]
                if 'SYN' in flags[0] and 'SYN+ACK' in flags[1] and 'ACK' in flags[2]:
                    handshakes.append({
                        'connection': connection,
                        'packets': packets[:3]
                    })
                    
        return handshakes
        
    def generate_statistics(self):
        """Generate analysis statistics"""
        duration = 0
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            
        stats = {
            'capture_info': {
                'total_packets': self.stats['total_packets'],
                'duration_seconds': round(duration, 2),
                'packets_per_second': round(self.stats['total_packets'] / duration, 2) if duration > 0 else 0,
                'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
                'end_time': self.stats['end_time'].isoformat() if self.stats['end_time'] else None,
            },
            'protocol_distribution': dict(self.stats['protocols']),
            'top_source_ips': dict(self.stats['src_ips'].most_common(10)),
            'top_destination_ips': dict(self.stats['dst_ips'].most_common(10)),
            'top_ports': dict(self.stats['ports'].most_common(10)),
            'tcp_flags_distribution': dict(self.stats['tcp_flags']),
            'packet_size_stats': {
                'min': min(self.stats['packet_sizes']) if self.stats['packet_sizes'] else 0,
                'max': max(self.stats['packet_sizes']) if self.stats['packet_sizes'] else 0,
                'avg': round(sum(self.stats['packet_sizes']) / len(self.stats['packet_sizes']), 2) if self.stats['packet_sizes'] else 0
            },
            'tcp_handshakes_detected': len(self.detect_tcp_handshakes())
        }
        
        return stats
        
    def print_statistics(self):
        """Print statistics to console"""
        stats = self.generate_statistics()
        
        print("\n" + "="*70)
        print("PACKET CAPTURE STATISTICS")
        print("="*70)
        
        print(f"\n📊 Capture Info:")
        print(f"  Total Packets: {stats['capture_info']['total_packets']}")
        print(f"  Duration: {stats['capture_info']['duration_seconds']} seconds")
        print(f"  Rate: {stats['capture_info']['packets_per_second']} packets/sec")
        
        print(f"\n🔌 Protocol Distribution:")
        for proto, count in sorted(stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['capture_info']['total_packets']) * 100
            print(f"  {proto:10s}: {count:5d} ({percentage:5.1f}%)")
            
        print(f"\n📡 Top Source IPs:")
        for ip, count in list(stats['top_source_ips'].items())[:5]:
            print(f"  {ip:15s}: {count} packets")
            
        print(f"\n🎯 Top Destination IPs:")
        for ip, count in list(stats['top_destination_ips'].items())[:5]:
            print(f"  {ip:15s}: {count} packets")
            
        print(f"\n🚪 Top Ports:")
        for port, count in list(stats['top_ports'].items())[:5]:
            print(f"  Port {port:5d}: {count} packets")
            
        print(f"\n🔒 TCP Flags:")
        for flags, count in sorted(stats['tcp_flags_distribution'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {flags:10s}: {count} packets")
            
        print(f"\n📦 Packet Sizes:")
        print(f"  Min: {stats['packet_size_stats']['min']} bytes")
        print(f"  Max: {stats['packet_size_stats']['max']} bytes")
        print(f"  Avg: {stats['packet_size_stats']['avg']} bytes")
        
        print(f"\n🤝 TCP Handshakes Detected: {stats['tcp_handshakes_detected']}")
        
        print("\n" + "="*70)
        
    def save_pcap(self, filename):
        """Save captured packets to PCAP file"""
        wrpcap(filename, self.packets)
        print(f"\n💾 Packets saved to: {filename}")
        
    def save_statistics_json(self, filename):
        """Save statistics to JSON file"""
        stats = self.generate_statistics()
        with open(filename, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"📊 Statistics saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(description='Real-time packet capture and analysis')
    parser.add_argument('--count', type=int, default=50, help='Number of packets to capture (default: 50)')
    parser.add_argument('--filter', type=str, default='', help='BPF filter (e.g., "tcp", "udp", "port 80")')
    parser.add_argument('--interface', type=str, default=None, help='Network interface (default: auto)')
    parser.add_argument('--save', action='store_true', help='Save packets to PCAP file')
    parser.add_argument('--timeout', type=int, default=None, help='Capture timeout in seconds')
    
    args = parser.parse_args()
    
    print("="*70)
    print("REAL-TIME PACKET CAPTURE & ANALYSIS")
    print("="*70)
    print(f"Packets to capture: {args.count}")
    print(f"Filter: {args.filter if args.filter else 'None (all packets)'}")
    print(f"Interface: {args.interface if args.interface else 'Auto-detect'}")
    print("="*70)
    print("\n🎯 Starting packet capture... (Press Ctrl+C to stop)\n")
    
    # Create analyzer
    analyzer = PacketAnalyzer()
    
    try:
        # Start capture
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=analyzer.packet_callback,
            count=args.count,
            timeout=args.timeout,
            store=False
        )
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Capture stopped by user")
        
    except PermissionError:
        print("\n❌ Error: Packet capture requires root/administrator privileges")
        print("   Run with: sudo python packet_capture.py")
        return
        
    # Print statistics
    analyzer.print_statistics()
    
    # Save if requested
    if args.save:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"captures/capture_{timestamp}.pcap"
        json_file = f"captures/stats_{timestamp}.json"
        
        analyzer.save_pcap(pcap_file)
        analyzer.save_statistics_json(json_file)


if __name__ == "__main__":
    main()