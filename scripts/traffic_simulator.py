"""
Network Traffic Simulator
=========================
"""

import random
import json
from datetime import datetime
from collections import Counter


class TrafficSimulator:
    """Simulate network traffic data"""
    
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP']
        self.ips = self._generate_ips()
        self.ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
        
    def _generate_ips(self):
        """Generate realistic IP addresses"""
        ips = []
        # Internal network
        for i in range(10):
            ips.append(f"192.168.1.{random.randint(1, 254)}")
        # External IPs
        for i in range(5):
            ips.append(f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
        return ips
        
    def simulate_capture(self, num_packets=100):
        """Simulate packet capture"""
        print(f"[Simulating] {num_packets} packets...")
        
        stats = {
            'capture_info': {
                'total_packets': num_packets,
                'duration_seconds': round(num_packets / random.uniform(10, 50), 2),
                'packets_per_second': round(random.uniform(10, 50), 2),
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat()
            },
            'protocol_distribution': {},
            'top_source_ips': {},
            'top_destination_ips': {},
            'top_ports': {},
            'tcp_flags_distribution': {},
            'packet_size_stats': {
                'min': random.randint(40, 60),
                'max': random.randint(1400, 1500),
                'avg': random.randint(400, 800)
            },
            'tcp_handshakes_detected': random.randint(5, 15)
        }
        
        # Simulate protocol distribution
        protocol_weights = {
            'TCP': 0.6,
            'UDP': 0.2,
            'ICMP': 0.05,
            'DNS': 0.1,
            'ARP': 0.05
        }
        
        protocol_counts = Counter()
        for _ in range(num_packets):
            proto = random.choices(self.protocols, weights=list(protocol_weights.values()))[0]
            protocol_counts[proto] += 1
            
        stats['protocol_distribution'] = dict(protocol_counts)
        
        # Simulate IP traffic
        src_counter = Counter()
        dst_counter = Counter()
        for _ in range(num_packets):
            src = random.choice(self.ips)
            dst = random.choice(self.ips)
            src_counter[src] += 1
            dst_counter[dst] += 1
            
        stats['top_source_ips'] = dict(src_counter.most_common(10))
        stats['top_destination_ips'] = dict(dst_counter.most_common(10))
        
        # Simulate port traffic
        port_counter = Counter()
        for _ in range(num_packets):
            port = random.choice(self.ports)
            port_counter[port] += random.randint(1, 3)
            
        stats['top_ports'] = dict(port_counter.most_common(10))
        
        # Simulate TCP flags
        tcp_flags = ['SYN', 'SYN+ACK', 'ACK', 'PSH+ACK', 'FIN+ACK', 'RST']
        flag_weights = [0.1, 0.1, 0.5, 0.2, 0.05, 0.05]
        
        flag_counter = Counter()
        tcp_packets = protocol_counts['TCP']
        for _ in range(tcp_packets):
            flag = random.choices(tcp_flags, weights=flag_weights)[0]
            flag_counter[flag] += 1
            
        stats['tcp_flags_distribution'] = dict(flag_counter)
        
        return stats
        
    def generate_simulated_packets_display(self, num_packets=20):
        """Generate display of simulated packets"""
        print("\n" + "="*70)
        print("SIMULATED PACKET CAPTURE")
        print("="*70 + "\n")
        
        for i in range(num_packets):
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            src_ip = random.choice(self.ips)
            dst_ip = random.choice(self.ips)
            proto = random.choice(self.protocols)
            
            if proto == 'TCP':
                src_port = random.choice(self.ports)
                dst_port = random.choice(self.ports)
                flags = random.choice(['S', 'SA', 'A', 'PA', 'FA', 'R'])
                print(f"[{timestamp}] {src_ip:15s} -> {dst_ip:15s} TCP {src_port} -> {dst_port} [{flags}] Len={random.randint(40, 1500)}")
                
            elif proto == 'UDP':
                src_port = random.choice(self.ports)
                dst_port = random.choice(self.ports)
                print(f"[{timestamp}] {src_ip:15s} -> {dst_ip:15s} UDP {src_port} -> {dst_port} Len={random.randint(40, 1500)}")
                
            elif proto == 'ICMP':
                icmp_type = random.choice([0, 3, 8, 11])
                print(f"[{timestamp}] {src_ip:15s} -> {dst_ip:15s} ICMP type={icmp_type} Len={random.randint(40, 100)}")
                
            elif proto == 'ARP':
                print(f"[{timestamp}] ARP {src_ip} -> {dst_ip} Len=42")
                
        print("\n" + "="*70)


def main():
    print("="*70)
    print("NETWORK TRAFFIC SIMULATOR")
    print("="*70)
    print("This simulates network traffic for testing purposes.\n")
    
    simulator = TrafficSimulator()
    
    # Display simulated packets
    simulator.generate_simulated_packets_display(30)
    
    # Generate statistics
    print("\n[Processing] Generating statistics...")
    stats = simulator.simulate_capture(1000)
    
    # Save statistics
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Determine correct path
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir) if 'scripts' in script_dir else script_dir
    captures_dir = os.path.join(project_root, 'captures')
    
    # Create captures directory if it doesn't exist
    os.makedirs(captures_dir, exist_ok=True)
    
    output_file = os.path.join(captures_dir, f"stats_{timestamp}_simulated.json")
    
    with open(output_file, 'w') as f:
        json.dump(stats, f, indent=2)
    
    print(f"[Success] Statistics saved to: {output_file}")
    print(f"\n[Next] Run: python scripts/generate_report.py --input {output_file}")
    
    # Print summary
    print("\n" + "="*70)
    print("TRAFFIC SUMMARY")
    print("="*70)
    print(f"Total Packets: {stats['capture_info']['total_packets']}")
    print(f"Duration: {stats['capture_info']['duration_seconds']}s")
    print(f"Rate: {stats['capture_info']['packets_per_second']} pkt/s")
    print(f"\nProtocol Distribution:")
    for proto, count in sorted(stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
        percentage = (count / stats['capture_info']['total_packets']) * 100
        print(f"  {proto:10s}: {count:4d} ({percentage:5.1f}%)")
    print("="*70)


if __name__ == "__main__":
    main()