from parser import get_ip_info, get_protocol, get_ports, detect_http
from utils import format_output
from stats import update_stats, stats
from logger import save_log
from dashboard import update_dashboard, show_dashboard

packet_counter = 0

def process_packet(packet):
    global packet_counter

    try:
        src, dst = get_ip_info(packet)
        proto = get_protocol(packet)
        sport, dport = get_ports(packet)
        size = len(packet)

        if src and dst:
            output = format_output(proto, src, dst, sport, dport, size)

            if detect_http(packet):
                output += " | HTTP"

            print(output)
            save_log(output)

            update_stats(proto)
            update_dashboard(src, dst)

            packet_counter += 1

            # Refresh dashboard every 10 packets
            if packet_counter % 10 == 0:
                show_dashboard(stats)

    except Exception as e:
        print(f"[PROCESS ERROR] {e}")