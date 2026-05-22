RULES = [
    {"type": "PORT_SCAN", "threshold": 10},
    {"type": "HTTP_FLOOD", "threshold": 50}
]

def apply_rules(packet_count, port_count):
    alerts = []

    if port_count > 10:
        alerts.append("Signature: Port Scan")

    if packet_count > 50:
        alerts.append("Signature: Traffic Flood")

    return alerts