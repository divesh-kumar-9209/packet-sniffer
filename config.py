import json

with open("config.json") as f:
    config = json.load(f)

THRESHOLD = config.get("threshold", 100)
PORT_SCAN_THRESHOLD = config.get("port_scan_threshold", 10)
TIME_WINDOW = config.get("time_window", 10)
COOLDOWN = config.get("cooldown", 15)

LOG_FILE = config.get("log_file", "packets.log")
REPORT_FILE = config.get("report_file", "report.json")

SAFE_IPS = config.get("safe_ips", [])