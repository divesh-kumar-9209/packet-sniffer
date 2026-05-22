stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0,
    "TOTAL": 0
}

def update_stats(proto):
    stats["TOTAL"] += 1

    if proto in stats:
        stats[proto] += 1
    else:
        stats["OTHER"] += 1

def print_stats():
    print("\n--- Final Packet Statistics ---")
    for key, value in stats.items():
        print(f"{key}: {value}")
        
def get_stats():
    return stats