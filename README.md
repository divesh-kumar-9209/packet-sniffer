# Packet Sniffer & Intrusion Detection Tool (Python)

## Overview

This project is a command-line based network packet sniffer with integrated basic Intrusion Detection System (IDS) capabilities. It captures live network traffic, parses protocol-level information, and detects anomalous behavior such as high traffic rates and potential port scanning activity.

The tool is designed to demonstrate core concepts of network monitoring, packet analysis, and security detection using Python and Scapy.

---

## Key Capabilities

### Packet Capture & Analysis
- Real-time packet sniffing using Scapy
- Supports TCP, UDP, and ICMP protocols
- Extracts source/destination IPs and port information
- Displays structured and timestamped output

### Command-Line Interface
- Interface selection support
- Berkeley Packet Filter (BPF) support for traffic filtering
- Continuous capture with graceful termination

### Output & Logging
- Human-readable packet summaries
- Controlled output sampling to prevent terminal flooding
- Persistent logging to file for later inspection

### Intrusion Detection Features
- Packet rate monitoring per source IP
- Detection of abnormal traffic spikes
- Port scan detection based on unique destination ports
- Alert system with cooldown mechanism to prevent duplicate alerts

### Configuration Management
- Centralized configuration via `config.json`
- Adjustable thresholds for detection logic
- No hardcoded values in detection pipeline

### Reporting
- Automatic report generation on termination
- JSON-based report containing traffic statistics

---

## Architecture

The application follows a modular design:
