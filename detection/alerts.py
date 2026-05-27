from collections import defaultdict
import time
from config import THRESHOLD, PORT_SCAN_THRESHOLD, TIME_WINDOW, COOLDOWN
from config import SAFE_IPS
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

ip_packet_count = defaultdict(int)
ip_port_count = defaultdict(set)

alert_time = {}

last_reset = time.time()


def ai_risk_score(packet_count, port_count):
    """
    Improved scoring (0–100 scale)
    """
    score = 0

    # Traffic weight (max 50)
    if packet_count > THRESHOLD:
        score += min(50, (packet_count / THRESHOLD) * 25)

    # Port scan weight (max 50)
    if port_count > PORT_SCAN_THRESHOLD:
        score += min(50, (port_count / PORT_SCAN_THRESHOLD) * 25)

    return int(score)


def get_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def colored_alert(message, severity, risk):
    """
    Returns formatted colored alert
    """

    if severity == "HIGH":
        return (
            Fore.RED +
            f"[HIGH ALERT] {message} | Risk Score: {risk}/100" +
            Style.RESET_ALL
        )

    elif severity == "MEDIUM":
        return (
            Fore.YELLOW +
            f"[MEDIUM ALERT] {message} | Risk Score: {risk}/100" +
            Style.RESET_ALL
        )

    else:
        return (
            Fore.GREEN +
            f"[LOW ALERT] {message} | Risk Score: {risk}/100" +
            Style.RESET_ALL
        )


def detect_anomalies(src_ip, dst_port):
    global last_reset

    now = time.time()

    # Ignore local traffic
    if src_ip.startswith("192.168"):
        return []

    # Ignore safe IPs
    if src_ip in SAFE_IPS:
        return []

    # Reset window
    if now - last_reset > TIME_WINDOW:
        ip_packet_count.clear()
        ip_port_count.clear()
        last_reset = now

    ip_packet_count[src_ip] += 1
    ip_port_count[src_ip].add(dst_port)

    alerts = []
    last_alert = alert_time.get(src_ip, 0)

    pkt = ip_packet_count[src_ip]
    ports = len(ip_port_count[src_ip])

    risk = ai_risk_score(pkt, ports)
    severity = get_severity(risk)

    # Cooldown control
    if now - last_alert > COOLDOWN:

        # Port Scan Detection
        if ports > PORT_SCAN_THRESHOLD:

            msg = f"Port scan detected from {src_ip}"

            alerts.append((
                colored_alert(msg, "HIGH", risk),
                "HIGH",
                risk
            ))

        # Traffic Flood
        elif pkt > THRESHOLD:

            msg = f"High traffic detected from {src_ip}"

            alerts.append((
                colored_alert(msg, severity, risk),
                severity,
                risk
            ))

        # Burst Detection
        elif pkt > THRESHOLD * 0.6:

            msg = f"Traffic spike detected from {src_ip}"

            alerts.append((
                colored_alert(msg, "LOW", risk),
                "LOW",
                risk
            ))

        if alerts:
            alert_time[src_ip] = now

    return alerts