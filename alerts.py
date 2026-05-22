from collections import defaultdict
import time

ip_packet_count = defaultdict(int)
ip_port_count = defaultdict(set)

THRESHOLD = 100   # packets per window
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10  # seconds

last_reset = time.time()

def detect_anomalies(src_ip, dst_port):
    global last_reset

    current_time = time.time()

    # Reset every TIME_WINDOW seconds
    if current_time - last_reset > TIME_WINDOW:
        ip_packet_count.clear()
        ip_port_count.clear()
        last_reset = current_time

    ip_packet_count[src_ip] += 1
    ip_port_count[src_ip].add(dst_port)

    alerts = []

    # 🚨 High traffic detection
    if ip_packet_count[src_ip] > THRESHOLD:
        alerts.append(f"[ALERT] High traffic from {src_ip}")

    # 🚨 Port scan detection
    if len(ip_port_count[src_ip]) > PORT_SCAN_THRESHOLD:
        alerts.append(f"[ALERT] Possible port scan from {src_ip}")

    return alerts