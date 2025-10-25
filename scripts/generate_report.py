"""
Automated Network Analysis Report Generator
===========================================

Generates comprehensive HTML reports from captured packets or JSON statistics.

Usage:
    python generate_report.py --input captures/stats_*.json
    python generate_report.py --pcap captures/capture_*.pcap
"""

import json
import argparse
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generate HTML analysis reports"""
    
    def __init__(self, stats_data):
        self.stats = stats_data
        
    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Protocol Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            padding: 20px;
            color: #333;
            font-weight: 400;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
            border-bottom: 1px solid #10b981;
        }}
        
        .header h1 {{
            font-size: 2.2em;
            margin-bottom: 12px;
            font-weight: 300;
            letter-spacing: 0.5px;
        }}
        
        .header p {{
            font-size: 1em;
            opacity: 0.85;
            font-weight: 300;
            letter-spacing: 0.3px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
            padding: 35px;
            background: #1e293b;
            border-radius: 8px;
            border-left: 3px solid #10b981;
            color: #e2e8f0;
        }}
        
        .section h2 {{
            color: #10b981;
            margin-bottom: 25px;
            font-size: 1.6em;
            display: flex;
            align-items: center;
            font-weight: 400;
            letter-spacing: 0.3px;
        }}
        
        .section h2::before {{
            content: '';
            margin-right: 0px;
            font-size: 1.2em;
        }}
        
        .section p {{
            color: #cbd5e1;
            font-weight: 300;
            line-height: 1.7;
            margin-bottom: 15px;
        }}
        
        .section h3 {{
            font-weight: 400;
            letter-spacing: 0.3px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-card {{
            background: #0f172a;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            transition: all 0.3s ease;
            border: 1px solid #334155;
        }}
        
        .stat-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.15);
            border-color: #10b981;
        }}
        
        .stat-label {{
            font-size: 0.8em;
            color: #94a3b8;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            font-weight: 500;
        }}
        
        .stat-value {{
            font-size: 2.8em;
            font-weight: 300;
            color: #10b981;
            letter-spacing: -0.5px;
        }}
        
        .stat-unit {{
            font-size: 0.5em;
            color: #64748b;
            margin-left: 5px;
        }}
        
        .protocol-bar {{
            margin: 15px 0;
        }}
        
        .protocol-bar-label {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.9em;
            color: #cbd5e1;
            font-weight: 400;
        }}
        
        .protocol-bar-fill {{
            height: 28px;
            background: linear-gradient(90deg, #10b981, #34d399);
            border-radius: 4px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            padding: 0 12px;
            color: white;
            font-weight: 500;
            font-size: 0.85em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #0f172a;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #334155;
        }}
        
        th, td {{
            padding: 16px 20px;
            text-align: left;
            color: #e2e8f0;
            font-weight: 400;
        }}
        
        th {{
            background: #1e293b;
            color: #10b981;
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 1.5px;
            border-bottom: 1px solid #10b981;
        }}
        
        tr:nth-child(even) {{
            background: #1a2332;
        }}
        
        tr:hover {{
            background: #334155;
            transition: background 0.2s ease;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            background: #1e293b;
            color: #94a3b8;
            border-top: 1px solid #334155;
        }}
        
        .badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 500;
            margin: 5px;
            letter-spacing: 0.3px;
        }}
        
        .badge-success {{
            background: rgba(16, 185, 129, 0.15);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        
        .badge-warning {{
            background: rgba(245, 158, 11, 0.15);
            color: #fcd34d;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}
        
        .badge-info {{
            background: rgba(6, 182, 212, 0.15);
            color: #67e8f9;
            border: 1px solid rgba(6, 182, 212, 0.3);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Protocol Analysis Report</h1>
            <p>Comprehensive Packet Capture & Traffic Analysis</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            {self._generate_summary_section()}
            {self._generate_protocol_section()}
            {self._generate_traffic_section()}
            {self._generate_tcp_section()}
            {self._generate_insights_section()}
        </div>
        
        <div class="footer">
            <p>Protocol Analysis Lab - Network Security & Analysis Tool</p>
            <p>Powered by Scapy & Python</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
        
    def _generate_summary_section(self):
        """Generate capture summary section"""
        info = self.stats['capture_info']
        
        return f"""
        <div class="section">
            <h2>Capture Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Packets</div>
                    <div class="stat-value">{info['total_packets']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Duration</div>
                    <div class="stat-value">{info['duration_seconds']}<span class="stat-unit">sec</span></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Capture Rate</div>
                    <div class="stat-value">{info['packets_per_second']}<span class="stat-unit">pkt/s</span></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Avg Packet Size</div>
                    <div class="stat-value">{self.stats['packet_size_stats']['avg']}<span class="stat-unit">bytes</span></div>
                </div>
            </div>
        </div>
        """
        
    def _generate_protocol_section(self):
        """Generate protocol distribution section"""
        protocols = self.stats['protocol_distribution']
        total = self.stats['capture_info']['total_packets']
        
        bars_html = ""
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            bars_html += f"""
            <div class="protocol-bar">
                <div class="protocol-bar-label">
                    <span><strong>{proto}</strong></span>
                    <span>{count} packets ({percentage:.1f}%)</span>
                </div>
                <div class="protocol-bar-fill" style="width: {percentage}%">
                    {percentage:.1f}%
                </div>
            </div>
            """
            
        return f"""
        <div class="section">
            <h2>Protocol Distribution</h2>
            <p>Analysis of network protocols detected in captured traffic:</p>
            {bars_html}
        </div>
        """
        
    def _generate_traffic_section(self):
        """Generate traffic analysis section"""
        top_srcs = list(self.stats['top_source_ips'].items())[:5]
        top_dsts = list(self.stats['top_destination_ips'].items())[:5]
        top_ports = list(self.stats['top_ports'].items())[:5]
        
        src_rows = "".join([f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in top_srcs])
        dst_rows = "".join([f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in top_dsts])
        port_rows = "".join([f"<tr><td>{port}</td><td>{self._get_port_service(port)}</td><td>{count}</td></tr>" 
                            for port, count in top_ports])
        
        return f"""
        <div class="section">
            <h2>Traffic Analysis</h2>
            
            <h3 style="margin-top: 20px; color: #10b981;">Top Source IPs</h3>
            <table>
                <thead>
                    <tr><th>IP Address</th><th>Packets</th></tr>
                </thead>
                <tbody>
                    {src_rows}
                </tbody>
            </table>
            
            <h3 style="margin-top: 30px; color: #10b981;">Top Destination IPs</h3>
            <table>
                <thead>
                    <tr><th>IP Address</th><th>Packets</th></tr>
                </thead>
                <tbody>
                    {dst_rows}
                </tbody>
            </table>
            
            <h3 style="margin-top: 30px; color: #10b981;">Top Ports</h3>
            <table>
                <thead>
                    <tr><th>Port</th><th>Service</th><th>Packets</th></tr>
                </thead>
                <tbody>
                    {port_rows}
                </tbody>
            </table>
        </div>
        """
        
    def _generate_tcp_section(self):
        """Generate TCP analysis section"""
        tcp_flags = self.stats.get('tcp_flags_distribution', {})
        handshakes = self.stats.get('tcp_handshakes_detected', 0)
        
        flag_rows = "".join([f"<tr><td>{flags}</td><td>{count}</td><td>{self._explain_tcp_flags(flags)}</td></tr>" 
                            for flags, count in sorted(tcp_flags.items(), key=lambda x: x[1], reverse=True)])
        
        return f"""
        <div class="section">
            <h2>TCP Analysis</h2>
            
            <div class="stats-grid" style="margin-bottom: 30px;">
                <div class="stat-card">
                    <div class="stat-label">TCP Handshakes Detected</div>
                    <div class="stat-value">{handshakes}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Unique Flag Combinations</div>
                    <div class="stat-value">{len(tcp_flags)}</div>
                </div>
            </div>
            
            <h3 style="color: #10b981;">TCP Flags Distribution</h3>
            <table>
                <thead>
                    <tr><th>Flags</th><th>Count</th><th>Meaning</th></tr>
                </thead>
                <tbody>
                    {flag_rows}
                </tbody>
            </table>
        </div>
        """
        
    def _generate_insights_section(self):
        """Generate insights and recommendations"""
        insights = self._analyze_traffic_patterns()
        
        insights_html = "".join([f'<span class="badge badge-{badge}">{insight}</span>' 
                                for insight, badge in insights])
        
        return f"""
        <div class="section">
            <h2>Traffic Insights</h2>
            <p>Automated analysis of captured traffic patterns:</p>
            <div style="margin-top: 20px;">
                {insights_html}
            </div>
            
            <h3 style="margin-top: 30px; color: #10b981;">Key Findings</h3>
            <ul style="line-height: 2; margin-top: 15px;">
                {self._generate_key_findings()}
            </ul>
        </div>
        """
        
    def _analyze_traffic_patterns(self):
        """Analyze traffic for insights"""
        insights = []
        protocols = self.stats['protocol_distribution']
        total = self.stats['capture_info']['total_packets']
        
        # Protocol dominance
        if 'TCP' in protocols and protocols['TCP'] / total > 0.7:
            insights.append(("TCP-dominated traffic (70%+)", "info"))
        if 'UDP' in protocols and protocols['UDP'] / total > 0.3:
            insights.append(("Significant UDP traffic", "info"))
        if 'ICMP' in protocols:
            insights.append(("ICMP packets detected", "warning"))
            
        # TCP handshakes
        handshakes = self.stats.get('tcp_handshakes_detected', 0)
        if handshakes > 0:
            insights.append((f"{handshakes} TCP connections established", "success"))
            
        # Packet rate
        rate = self.stats['capture_info']['packets_per_second']
        if rate > 100:
            insights.append(("High traffic rate (>100 pkt/s)", "warning"))
        elif rate < 10:
            insights.append(("Low traffic rate (<10 pkt/s)", "info"))
            
        return insights
        
    def _generate_key_findings(self):
        """Generate key findings list"""
        findings = []
        protocols = self.stats['protocol_distribution']
        
        # Most common protocol
        if protocols:
            top_proto = max(protocols.items(), key=lambda x: x[1])
            findings.append(f"<li><strong>Dominant Protocol:</strong> {top_proto[0]} ({top_proto[1]} packets)</li>")
            
        # Traffic rate
        rate = self.stats['capture_info']['packets_per_second']
        findings.append(f"<li><strong>Average Traffic Rate:</strong> {rate} packets/second</li>")
        
        # Packet sizes
        size_stats = self.stats['packet_size_stats']
        findings.append(f"<li><strong>Packet Size Range:</strong> {size_stats['min']} - {size_stats['max']} bytes (avg: {size_stats['avg']})</li>")
        
        # TCP connections
        handshakes = self.stats.get('tcp_handshakes_detected', 0)
        if handshakes > 0:
            findings.append(f"<li><strong>TCP Connections:</strong> {handshakes} successful 3-way handshakes detected</li>")
            
        # Unique IPs
        unique_srcs = len(self.stats['top_source_ips'])
        unique_dsts = len(self.stats['top_destination_ips'])
        findings.append(f"<li><strong>Network Diversity:</strong> {unique_srcs} source IPs, {unique_dsts} destination IPs</li>")
        
        return "\n".join(findings)
        
    def _get_port_service(self, port):
        """Get common service name for port"""
        common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt"
        }
        return common_ports.get(int(port), "Unknown")
        
    def _explain_tcp_flags(self, flags):
        """Explain TCP flag combinations"""
        explanations = {
            'SYN': 'Connection initiation',
            'SYN+ACK': 'Connection acknowledgment',
            'ACK': 'Acknowledgment',
            'FIN': 'Connection termination',
            'FIN+ACK': 'Acknowledgment of termination',
            'RST': 'Connection reset',
            'PSH': 'Push data immediately',
            'PSH+ACK': 'Push with acknowledgment'
        }
        return explanations.get(flags, 'Multiple flags combination')


def main():
    parser = argparse.ArgumentParser(description='Generate network analysis report')
    parser.add_argument('--input', type=str, required=True, help='Input JSON statistics file')
    parser.add_argument('--output', type=str, default=None, help='Output HTML file')
    
    args = parser.parse_args()
    
    # Load statistics
    print(f"[Loading] Statistics from: {args.input}")
    with open(args.input, 'r') as f:
        stats = json.load(f)
    
    # Generate report
    print("[Generating] HTML report...")
    generator = ReportGenerator(stats)
    html = generator.generate_html_report()
    
    # Determine output path
    if args.output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Try to find reports directory
        import os
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir) if 'scripts' in script_dir else script_dir
        reports_dir = os.path.join(project_root, 'reports')
        
        # Create reports directory if it doesn't exist
        os.makedirs(reports_dir, exist_ok=True)
        
        args.output = os.path.join(reports_dir, f"analysis_report_{timestamp}.html")
    else:
        # Create parent directory if needed
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    
    with open(args.output, 'w') as f:
        f.write(html)
    
    print(f"[Success] Report generated: {args.output}")
    print(f"\n[Browser] Open: file://{Path(args.output).absolute()}")


if __name__ == "__main__":
    main()