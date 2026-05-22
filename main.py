import argparse
from scapy.all import sniff, get_if_list
from sniffer import process_packet
from stats import print_stats
from config import DEFAULT_FILTER

def list_interfaces():
    print("\nAvailable Network Interfaces:")
    for i, iface in enumerate(get_if_list()):
        print(f"{i}: {iface}")
    print()

def start_sniffer(interface, filter_rule):
    print(f"[*] Interface: {interface}")
    print(f"[*] Filter: {filter_rule}")
    print("[*] Press CTRL+C to stop\n")

    sniff(
        iface=interface,
        filter=filter_rule,
        prn=process_packet,
        store=False
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer v3")

    parser.add_argument("-f", "--filter", default=DEFAULT_FILTER)
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("--list", action="store_true", help="List interfaces")

    args = parser.parse_args()

    try:
        if args.list:
            list_interfaces()
        else:
            start_sniffer(args.interface, args.filter)

    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user")
        print_stats()

    except Exception as e:
        print(f"[ERROR] {e}")