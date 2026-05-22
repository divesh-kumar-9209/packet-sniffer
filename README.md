# Packet Sniffer & Intrusion Detection System (Python)

## Overview

This project is a command-line based packet sniffer with integrated Intrusion Detection System (IDS) capabilities. It captures live network traffic, analyzes packets, and detects suspicious behavior using rule-based and heuristic techniques.

The tool is designed to demonstrate core concepts of network monitoring, traffic analysis, and anomaly detection in a modular and scalable architecture.

---

## Features

### Packet Capture
- Real-time packet sniffing using Scapy
- Supports TCP, UDP, and ICMP protocols
- Extracts source/destination IPs and ports

### CLI Functionality
- Interface selection
- Traffic filtering using BPF syntax
- Continuous capture with graceful termination

### Output & Logging
- Structured and readable output
- Timestamp and packet size display
- Controlled output (sampling to avoid flooding)
- Logging to file

### Intrusion Detection (IDS)
- Packet rate monitoring
- Port scan detection
- Suspicious traffic identification
- Severity classification (LOW / MEDIUM / HIGH)
- Risk scoring model (0–100 scale)
- Cooldown-based alert system

### Configuration
- External configuration via `config.json`
- Adjustable thresholds and detection parameters
- Support for safe/whitelisted IPs

### Reporting
- Automatic report generation on exit
- JSON-based statistics output

---

## Project Structure
packet-sniffer/
│
├── core/
│ ├── sniffer.py
│ ├── parser.py
│ ├── stats.py
│
├── detection/
│ ├── alerts.py
│ ├── rules.py
│ ├── ml_model.py
│
├── interface/
│ ├── gui.py
│
├── utils/
│ ├── logger.py
│ ├── utils.py
│
├── config.json
├── config.py
├── main.py
├── report.py
├── requirements.txt
└── README.md


---

## Installation

```bash
pip install -r requirements.txt

Usage
List Interfaces
python main.py --list
Run Sniffer
python main.py -i 3 -f tcp
Example Filters
python main.py -f tcp
python main.py -f "port 80"
python main.py -f "tcp and port 443"
Stopping Execution

Press:

CTRL + C

This will:

Stop packet capture
Generate a report file
Sample Output
[12:45:10] TCP | 192.168.0.100 -> 142.250.82.252 | 60B | 49909 -> 443
[HIGH] Port scan detected from 192.168.0.100 | Risk: 85

Configuration

config.json

{
  "threshold": 100,
  "port_scan_threshold": 10,
  "time_window": 10,
  "cooldown": 15,
  "log_file": "packets.log",
  "report_file": "report.json",
  "safe_ips": []
}
Limitations
Detection is threshold-based and may generate false positives
No deep packet inspection
Not intended for production use
Future Improvements
Machine learning-based anomaly detection
GUI dashboard enhancements
Protocol-specific analysis (HTTP, DNS)
Advanced threat classification
License

This project is intended for educational purposes.


---

# 📦 3. FINAL `requirements.txt`

```txt
scapy