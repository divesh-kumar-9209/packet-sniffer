from collections import defaultdict
import time

from config import (
    THRESHOLD,
    PORT_SCAN_THRESHOLD,
    TIME_WINDOW,
    COOLDOWN,
    SAFE_IPS
)

from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True, convert=True)

ip_packet_count = defaultdict(int)
ip_port_count = defaultdict(set)

alert_time = {}

last_reset = time.time()


def ai_risk_score(packet_count, port_count):
    """
    Calculate AI-inspired risk score (0–100)
    """

    score = 0

    # Traffic-based scoring
    if packet_count > THRESHOLD:
        score += min(
            50,
            int((packet_count / THRESHOLD) * 25)
        )

    # Port-scan-based scoring
    if port_count > PORT_SCAN_THRESHOLD:
        score += min(
            50,
            int((port_count / PORT_SCAN_THRESHOLD) * 25)
        )

    return min(score, 100)


def get_severity(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


def colored_alert(message, severity, risk):
    """
    Generate formatted colored alerts
    """

    if severity == "HIGH":

        return (
            Fore.RED
            + f"[HIGH ALERT] {message} | Risk Score: {risk}/100"
            + Style.RESET_ALL
        )

    elif severity == "MEDIUM":

        return (
            Fore.YELLOW
            + f"[MEDIUM ALERT] {message} | Risk Score: {risk}/100"
            + Style.RESET_ALL
        )

    return (
        Fore.GREEN
        + f"[LOW ALERT] {message} | Risk Score: {risk}/100"
        + Style.RESET_ALL
    )


def detect_anomalies(src_ip, dst_port):

    global last_reset

    now = time.time()

    # Ignore localhost traffic
    if src_ip.startswith("127."):
        return []

    # Ignore local network traffic
    if src_ip.startswith("192.168"):
        return []

    # Ignore multicast traffic
    if src_ip.startswith("224."):
        return []

    # Ignore broadcast traffic
    if src_ip.startswith("255."):
        return []

    # Ignore whitelisted IPs
    if src_ip in SAFE_IPS:
        return []

    # Reset counters after time window
    if now - last_reset > TIME_WINDOW:

        ip_packet_count.clear()
        ip_port_count.clear()

        last_reset = now

    # Update counters
    ip_packet_count[src_ip] += 1
    ip_port_count[src_ip].add(dst_port)

    alerts = []

    last_alert = alert_time.get(src_ip, 0)

    pkt = ip_packet_count[src_ip]
    ports = len(ip_port_count[src_ip])

    risk = ai_risk_score(pkt, ports)

    severity = get_severity(risk)

    # Cooldown system
    if now - last_alert > COOLDOWN:

        # HIGH ALERT → Port Scan
        if ports > PORT_SCAN_THRESHOLD:

            msg = f"Port scan detected from {src_ip}"

            alerts.append((
                colored_alert(
                    msg,
                    "HIGH",
                    max(risk, 75)
                ),
                "HIGH",
                max(risk, 75)
            ))

        # MEDIUM/HIGH ALERT → Traffic Flood
        elif pkt > THRESHOLD:

            msg = f"High traffic detected from {src_ip}"

            alerts.append((
                colored_alert(
                    msg,
                    severity,
                    risk
                ),
                severity,
                risk
            ))

        # LOW ALERT → Traffic Spike
        elif pkt > THRESHOLD * 0.6:

            msg = f"Traffic spike detected from {src_ip}"

            alerts.append((
                colored_alert(
                    msg,
                    "LOW",
                    risk
                ),
                "LOW",
                risk
            ))

        # Update cooldown timer
        if alerts:
            alert_time[src_ip] = now

    return alerts