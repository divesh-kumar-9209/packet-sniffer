from collections import defaultdict
import time
from config import THRESHOLD, PORT_SCAN_THRESHOLD, TIME_WINDOW, COOLDOWN

ip_packet_count = defaultdict(int)
ip_port_count = defaultdict(set)

alert_time = {}

last_reset = time.time()

# Optional filters
SAFE_IPS = ["142.250.82.252"]

def ai_risk_score(packet_count, port_count):
    score = 0

    if packet_count > THRESHOLD:
        score += 50

    if port_count > PORT_SCAN_THRESHOLD:
        score += 50

    return score


def detect_anomalies(src_ip, dst_port):
    global last_reset

    now = time.time()

    # Ignore local traffic (optional logic)
    if src_ip.startswith("192.168"):
        return []

    if src_ip in SAFE_IPS:
        return []

    if now - last_reset > TIME_WINDOW:
        ip_packet_count.clear()
        ip_port_count.clear()
        last_reset = now

    ip_packet_count[src_ip] += 1
    ip_port_count[src_ip].add(dst_port)

    alerts = []
    last_alert = alert_time.get(src_ip, 0)

    if now - last_alert > COOLDOWN:

        pkt = ip_packet_count[src_ip]
        ports = len(ip_port_count[src_ip])

        risk = ai_risk_score(pkt, ports)

        if ports > PORT_SCAN_THRESHOLD:
            alerts.append(("Port scan detected from " + src_ip, "HIGH", risk))

        elif pkt > THRESHOLD:
            alerts.append(("High traffic from " + src_ip, "MEDIUM", risk))

        if alerts:
            alert_time[src_ip] = now

    return alerts