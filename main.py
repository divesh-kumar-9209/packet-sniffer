import argparse

from scapy.all import sniff, get_if_list, get_if_addr

from core.sniffer import process_packet
from report import generate_report


def list_interfaces():

    print("\nAvailable Network Interfaces:\n")

    interfaces = get_if_list()

    for i, iface in enumerate(interfaces):

        try:
            ip = get_if_addr(iface)

        except Exception:
            ip = "No IP"

        status = "ACTIVE" if ip != "0.0.0.0" else "INACTIVE"

        print(f"{i}: {iface}")
        print(f"   ↳ IP: {ip} | Status: {status}\n")


def get_interface_map():

    interfaces = get_if_list()

    return {str(i): iface for i, iface in enumerate(interfaces)}


def start_sniffer(interface, filter_rule):

    print(f"[*] Interface: {interface}")
    print(f"[*] Filter: {filter_rule}")
    print("[*] Press CTRL+C to stop\n")

    try:

        sniff(
            iface=interface,
            filter=filter_rule,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n[!] Stopping packet capture...")

    finally:

        try:
            generate_report()

        except Exception as e:
            print(f"[ERROR] Report generation failed: {e}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Packet Sniffer IDS v8"
    )

    parser.add_argument(
        "-f",
        "--filter",
        default=""
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Interface index or name"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List interfaces"
    )

    args = parser.parse_args()

    iface_map = get_interface_map()

    try:

        if args.list:

            list_interfaces()

        else:

            selected_iface = args.interface

            # User selected interface by index
            if selected_iface in iface_map:
                selected_iface = iface_map[selected_iface]

            # Auto-select first active interface
            if not selected_iface:

                for iface in iface_map.values():

                    try:
                        ip = get_if_addr(iface)

                        if ip != "0.0.0.0":
                            selected_iface = iface
                            break

                    except Exception:
                        continue

            if not selected_iface:
                raise Exception("No active interface found")

            start_sniffer(
                selected_iface,
                args.filter
            )

    except Exception as e:

        print(f"[ERROR] {e}")