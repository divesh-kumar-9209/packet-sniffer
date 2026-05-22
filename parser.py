from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

def get_ip_info(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    return None, None

def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"

def get_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    return None, None

def detect_http(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if b"HTTP" in payload or b"GET" in payload:
            return True
    return False