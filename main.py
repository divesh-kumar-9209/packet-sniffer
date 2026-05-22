import argparse
from scapy.all import sniff, get_if_list, get_if_list, get_if_addr
from sniffer import process_packet
from stats import print_stats
from report import generate_report

def list_interfaces():
    print("\nAvailable Network Interfaces:\n")

    interfaces = get_if_list()

    for i, iface in enumerate(interfaces):
        try:
            ip = get_if_addr(iface)
        except:
            ip = "No IP"

        status = "ACTIVE" if ip != "0.0.0.0" else "INACTIVE"

        print(f"{i}: {iface}")
        print(f"   ↳ IP: {ip} | Status: {status}\n")

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

def get_interface_map():
    interfaces = get_if_list()
    mapping = {}

    for i, iface in enumerate(interfaces):
        mapping[str(i)] = iface

    return mapping

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer v3")

    parser.add_argument("-f", "--filter", default="")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("--list", action="store_true", help="List interfaces")

    args = parser.parse_args()

    try:
        iface_map = get_interface_map()
        if args.list:
            list_interfaces()
        else:
            selected_iface = args.interface

        # Allow index instead of full NPF name  
            iface_map = get_interface_map()
            if selected_iface in iface_map:
                selected_iface = iface_map[selected_iface]

                start_sniffer(selected_iface, args.filter)

    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        generate_report()

    except Exception as e:
        print(f"[ERROR] {e}")