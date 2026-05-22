from core.parser import get_ip_info, get_protocol, get_ports, detect_http
from utils.utils import format_output, format_alert
from core.stats import update_stats
from utils.logger import save_log
from detection.alerts import detect_anomalies

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

            # Controlled output
            if counter % 25 == 0:
                output = format_output(proto, src, dst, sport, dport, size)

                if detect_http(packet):
                    output += " | HTTP"

                print(output)
                save_log(output)

            update_stats(proto)

            alerts = detect_anomalies(src, dport)

            for msg, severity, risk in alerts:
                alert_line = f"{msg} | Risk Score: {risk}"
                formatted = format_alert(alert_line, severity)

                print(formatted)
                save_log(alert_line)

    except:
        pass