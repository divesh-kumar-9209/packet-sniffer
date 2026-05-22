# 🔍 Packet Sniffer & Mini IDS (Python)

A command-line based packet sniffer and basic Intrusion Detection System (IDS) built using Scapy.

This tool captures live network traffic, analyzes packets, and detects suspicious behavior such as high traffic and potential port scanning.

---

## 🚀 Features

### 🟢 Packet Sniffing
- Capture live network packets in real-time
- Supports TCP, UDP, ICMP protocols
- Extracts IP addresses and ports

### 🟢 CLI Tool
- Interface selection (`--list`, `-i`)
- Custom filters (`-f tcp`, `port 80`, etc.)
- Continuous capture with graceful stop

### 🟢 Output & Logging
- Structured and readable output
- Timestamp + packet size
- Controlled output (reduces spam)
- Logs saved to file

### 🟢 IDS (Intrusion Detection System) Features
- Packet rate monitoring
- Suspicious IP detection
- Port scan detection
- Alert system with cooldown (no spam)

### 🟢 Config System
- All thresholds configurable via `config.json`
- No hardcoding required

### 🟢 Reporting
- Generates JSON report on exit
- Includes packet statistics

---

## 📂 Project Structure
