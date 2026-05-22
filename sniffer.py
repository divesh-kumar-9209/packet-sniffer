from parser import get_ip_info, get_protocol, get_ports, detect_http
from utils import format_output
from stats import update_stats
from logger import save_log

def process_packet(packet):
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

    except Exception as e:
        print(f"[PROCESS ERROR] {e}")