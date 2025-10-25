# Network Protocol Analysis Lab

> **Real-Time Packet Capture, Analysis & Automated Reporting System**

---

## Project Overview

A network protocol analysis toolkit built with Python and Scapy for deep packet inspection, real-time traffic monitoring, and automated security analysis. 

### Key Features

- **Real-Time Packet Capture**: Scapy-based live packet capture with protocol filtering
- **Deep Protocol Analysis**: TCP, UDP, ICMP, DNS, ARP packet inspection
- **TCP Handshake Detection**: Automated 3-way handshake identification
- **Automated Reporting**: Readable HTML reports with traffic visualizations
- **Traffic Simulation**: Built-in traffic generator for testing
- **Security Insights**: Anomaly detection and security pattern analysis
<img width="699" height="499" alt="截屏2025-10-26 上午10 18 49" src="https://github.com/user-attachments/assets/c46565ef-4a1c-4d6c-8c2f-dc8e6e1233f0" />

  

---

## Architecture

```
┌─────────────────────────────────────┐
│     Network Interface (eth0)        │
└──────────────┬──────────────────────┘
               │
        ┌──────▼───────┐
        │  Scapy       │  ← Packet Capture
        │  Sniffer     │
        └──────┬───────┘
               │
        ┌──────▼────────┐
        │  Packet       │  ← Protocol Analysis
        │  Analyzer     │     • TCP/UDP/ICMP
        └──────┬────────┘     • Flags & Ports
               │              • IP Traffic
        ┌──────▼────────┐
        │  Statistics   │  ← Data Aggregation
        │  Engine       │
        └──────┬────────┘
               │
        ┌──────▼────────┐
        │  Report       │  ← HTML Generation
        │  Generator    │
        └───────────────┘
```

---
### Installation

```bash
# Clone or download the project
cd protocol-analysis-lab

# Verify structure
ls -la
# scripts/    - Python scripts
# captures/   - Saved captures
# reports/    - HTML reports
```

---

## Usage Examples

### 1. **Simulate Traffic** (No root required)

```bash
cd scripts
python traffic_simulator.py
```

**Output:**
```
======================================================================
NETWORK TRAFFIC SIMULATOR
======================================================================

[12:34:56.123] 192.168.1.100   -> 8.8.8.8         TCP 443 -> 80 [SA] Len=60
[12:34:56.125] 192.168.1.101   -> 192.168.1.1    UDP 53 -> 5353 Len=89
...

Statistics saved to: captures/stats_*_simulated.json
```

### 2. **Generate HTML Report**

```bash
python scripts/generate_report.py --input captures/stats_*.json
```

**Output:**
```
Loading statistics from: captures/**.json
Generating HTML report...
Report generated: reports/*.html

🌐 Open in browser: file:///path/to/reports/analysis_report_*.html
```

### 3. **Real Packet Capture** (Requires sudo/admin)

```bash
# Capture 100 packets
sudo python packet_capture.py --count 100

# Capture TCP only
sudo python packet_capture.py --filter "tcp" --count 50

# Capture and save
sudo python packet_capture.py --count 200 --save
```

**Output:**
```
======================================================================
REAL-TIME PACKET CAPTURE & ANALYSIS
======================================================================
Packets to capture: 100
Filter: tcp
======================================================================

[12:45:30.123] 192.168.1.100   -> 93.184.216.34  TCP 54321 -> 443 [SA]  Len=60
[12:45:30.125] 93.184.216.34   -> 192.168.1.100  TCP 443 -> 54321 [A]   Len=52
...

======================================================================
PACKET CAPTURE STATISTICS
======================================================================

Capture Info:
  Total Packets: 100
  Duration: 15.3 seconds
  Rate: 6.54 packets/sec

Protocol Distribution:
  TCP       :    85 ( 85.0%)
  UDP       :    10 ( 10.0%)
  ICMP      :     5 (  5.0%)

TCP Handshakes Detected: 12
======================================================================
```

---

##  Project Structure

---

## Sample Report

The generated HTML report includes:

### **Capture Summary**
- Total packets captured
- Capture duration
- Packets per second
- Average packet size

### **Protocol Distribution**
- Visual bar charts
- Percentage breakdown
- TCP/UDP/ICMP/DNS/ARP analysis

### **Traffic Analysis**
- Top source IPs
- Top destination IPs
- Most active ports
- Service identification

### **TCP Analysis**
- TCP handshakes detected
- Flag combinations (SYN, ACK, FIN, etc.)
- Connection patterns

### **Security Insights**
- Traffic anomalies
- Suspicious patterns
- Security recommendations

---

## Advanced Features

### Custom Filters
```bash
# Capture only HTTPS traffic
sudo python packet_capture.py --filter "tcp port 443"

# Capture DNS queries
sudo python packet_capture.py --filter "udp port 53"

# Capture from specific IP
sudo python packet_capture.py --filter "host 192.168.1.100"
```

### Protocol-Specific Analysis
- TCP connection tracking
- UDP stream analysis  
- ICMP type identification
- ARP table inspection

---
