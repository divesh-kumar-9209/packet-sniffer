from collections import defaultdict
import os

ip_count = defaultdict(int)

def update_dashboard(src, dst):
    ip_count[src] += 1
    ip_count[dst] += 1

def show_dashboard(stats):
    os.system('cls')  # Windows साफ screen

    print("=== LIVE TRAFFIC DASHBOARD ===\n")

    print("Protocol Stats:")
    for key, value in stats.items():
        print(f"{key}: {value}")

    print("\nTop Active IPs:")

    sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:5]:
        print(f"{ip} → {count} packets")