import socket

from core.parser import get_ip_info, get_protocol, get_ports, detect_http
from utils.utils import format_output, format_alert
from core.stats import update_stats
from utils.logger import save_log
from detection.alerts import detect_anomalies
from config import SAFE_IPS

counter = 0


def resolve_hostname(ip):
    """
    Resolve hostname from IP address
    """

    try:
        hostname = socket.getfqdn(ip)

        # If hostname not resolved properly
        if hostname == ip:
            return "Unknown"

        return hostname

    except:
        return "Unknown"


def process_packet(packet):
    global counter

    try:
        src, dst = get_ip_info(packet)
        proto = get_protocol(packet)
        sport, dport = get_ports(packet)
        size = len(packet)

        if src and dst:

            counter += 1

            # Resolve hostname only for external suspicious IPs
            hostname = ""

            if (
                not src.startswith("192.168")
                and src not in SAFE_IPS
            ):
                resolved = resolve_hostname(src)

                if resolved != "Unknown":
                    hostname = f" ({resolved})"

            # Controlled output
            if counter % 25 == 0:

                output = format_output(
                    proto,
                    f"{src}{hostname}",
                    dst,
                    sport,
                    dport,
                    size
                )

                if detect_http(packet):
                    output += " | HTTP"

                print(output)
                save_log(output)

            update_stats(proto)

            alerts = detect_anomalies(src, dport)

            for msg, severity, risk in alerts:

                formatted = format_alert(msg, severity)

                print(formatted)

                save_log(
                    f"{severity} ALERT | {msg} | Risk Score: {risk}"
                )

    except Exception as e:
        print(f"[ERROR] {e}")