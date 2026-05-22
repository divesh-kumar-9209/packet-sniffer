from datetime import datetime

def format_output(proto, src, dst, sport, dport, size):
    time = datetime.now().strftime("%H:%M:%S")

    if sport and dport:
        return f"[{time}] {proto} | {src} -> {dst} | Ports {sport} -> {dport} | Size: {size} bytes"
    
    return f"[{time}] {proto} | {src} -> {dst} | Size: {size} bytes"