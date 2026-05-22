import json

with open("config.json") as f:
    config = json.load(f)

THRESHOLD = config["threshold"]
PORT_SCAN_THRESHOLD = config["port_scan_threshold"]
TIME_WINDOW = config["time_window"]
COOLDOWN = config["cooldown"]
LOG_FILE = config["log_file"]
REPORT_FILE = config["report_file"]