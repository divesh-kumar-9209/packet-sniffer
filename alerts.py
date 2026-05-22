from collections import defaultdict
import time

ip_packet_count = defaultdict(int)
ip_port_count = defaultdict(set)

# Track alert states (IMPORTANT)
alerted_high_traffic = set()
alerted_port_scan = set()

THRESHOLD = 100
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10

last_reset = time.time()

def detect_anomalies(src_ip, dst_port):
    global last_reset

    current_time = time.time()

    # 🔁 Reset window
    if current_time - last_reset > TIME_WINDOW:
        ip_packet_count.clear()
        ip_port_count.clear()

        alerted_high_traffic.clear()
        alerted_port_scan.clear()

        last_reset = current_time

    ip_packet_count[src_ip] += 1
    ip_port_count[src_ip].add(dst_port)

    alerts = []

    # 🚨 High traffic alert (ONLY ONCE PER WINDOW)
    if (
        ip_packet_count[src_ip] > THRESHOLD
        and src_ip not in alerted_high_traffic
    ):
        alerts.append(f"[ALERT] High traffic from {src_ip}")
        alerted_high_traffic.add(src_ip)

    # 🚨 Port scan alert (ONLY ONCE PER WINDOW)
    if (
        len(ip_port_count[src_ip]) > PORT_SCAN_THRESHOLD
        and src_ip not in alerted_port_scan
    ):
        alerts.append(f"[ALERT] Possible port scan from {src_ip}")
        alerted_port_scan.add(src_ip)

    return alerts