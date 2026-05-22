from parser import get_ip_info, get_protocol, get_ports, detect_http
from utils import format_output
from stats import update_stats
from logger import save_log
from alerts import detect_anomalies

counter = 0

def process_packet(packet):
    global counter

    try:
        src, dst = get_ip_info(packet)
        proto = get_protocol(packet)
        sport, dport = get_ports(packet)
        size = len(packet)

        if src and dst:
            counter += 1

            # 🔹 Show only every 20th packet (NO SPAM)
            if counter % 20 == 0:
                output = format_output(proto, src, dst, sport, dport, size)

                if detect_http(packet):
                    output += " | HTTP"

                print(output)
                save_log(output)

            # 🔹 Always update stats
            update_stats(proto)

            # 🔹 Alerts (real-time, not sampled)
            alerts = detect_anomalies(src, dport)

            for alert in alerts:
                print(alert)
                save_log(alert)

    except Exception:
        pass