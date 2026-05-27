# 🛡️ Packet Sniffer & Intrusion Detection System

A Python-based real-time network monitoring and intrusion detection tool that captures live traffic, detects suspicious activity, and generates alerts using custom rule-based anomaly detection.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)

---

## Features

- Real-time packet sniffing using Scapy
- Port scan and traffic flood detection
- Severity-based risk scoring system
- Live terminal dashboard
- Colored alerts using Colorama
- Hostname resolution for suspicious IPs
- JSON report generation
- Configurable thresholds and safe IPs
- BPF filter support

---

## Technologies Used

Python • Scapy • Socket Programming • Packet Analysis • Colorama • JSON Reporting • BPF Filters

---

## How It Works

```text
Live Traffic
     ↓
Packet Capture (Scapy)
     ↓
Packet Parsing & Statistics
     ↓
Anomaly Detection Engine
     ↓
Risk Scoring
     ↓
Dashboard + Alerts + JSON Report
```

---

## Project Structure

```text
packet-sniffer/
│
├── core/
├── detection/
├── utils/
├── config.json
├── main.py
├── dashboard.py
├── report.py
└── requirements.txt
```

---

## Installation

```bash
git clone https://github.com/divesh-kumar-9209/packet-sniffer.git

cd packet-sniffer

pip install -r requirements.txt
```

### Windows
Run terminal as Administrator.

### Linux
Run with:

```bash
sudo python main.py
```

---

## Usage

### List Interfaces

```bash
python main.py --list
```

### Start Sniffing

```bash
python main.py -i 0

python main.py -i 0 -f tcp

python main.py -i 0 -f "tcp and port 443"
```

### Stop Capture

```text
Press CTRL + C to generate report.json
```

---

## Sample Output

```text
[21:24:50] TCP | 142.250.82.252 (googleusercontent.com) -> 192.168.0.100 | Ports 443 -> 49909 | Size: 914 bytes

=== LIVE TRAFFIC DASHBOARD ===

TCP: 487
UDP: 32
ICMP: 5

[HIGH ALERT] Port scan detected from 10.0.0.5 | Risk Score: 85/100

[MEDIUM ALERT] High traffic detected from 10.0.0.9 | Risk Score: 62/100
```

---

## Configuration

```json
{
  "threshold": 100,
  "port_scan_threshold": 10,
  "time_window": 10,
  "cooldown": 15,
  "safe_ips": ["142.250.82.252"]
}
```

---

## Detection Logic

- Port scan detection based on unique destination ports
- Traffic flood detection using packet thresholds
- Burst anomaly detection for sudden spikes
- Risk scoring system with LOW / MEDIUM / HIGH severity
- Cooldown system to reduce duplicate alerts

---

## BPF Filter Examples

```bash
tcp
udp
port 80
port 443
tcp and port 22
host 192.168.1.1
```

---

## Limitations

- Threshold-based detection may create false positives
- No deep packet inspection
- Designed for controlled and educational environments
- Windows requires Npcap for packet capture

---

## Planned Improvements

- Machine learning anomaly detection
- GeoIP integration
- Flask web dashboard
- Offline PCAP analysis
- Email/webhook alerting

---

## Tested On

- Windows 10 & 11 with Npcap
- scanme.nmap.org

---

## Author

**Divesh Kumar**  
CSE Undergraduate | Cybersecurity Enthusiast

GitHub:  
https://github.com/divesh-kumar-9209/packet-sniffer

---

## Disclaimer

This project is intended for educational and ethical cybersecurity research purposes only.