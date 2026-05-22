import argparse
from scapy.all import sniff
from sniffer import process_packet
from stats import print_stats

def start_sniffer(filter_rule):
    print(f"[*] Starting Packet Sniffer with filter: {filter_rule}\n")
    sniff(filter=filter_rule, prn=process_packet, store=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    
    parser.add_argument(
        "-f", "--filter",
        help="BPF filter (e.g. tcp, udp, icmp, port 80)",
        default=""
    )

    args = parser.parse_args()

    try:
        start_sniffer(args.filter)
    except KeyboardInterrupt:
        print("\n[!] Stopping Sniffer...")
        print_stats()