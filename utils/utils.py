from datetime import datetime

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def format_output(proto, src, dst, sport, dport, size):
    time = datetime.now().strftime("%H:%M:%S")

    base = f"[{time}] {proto} | {src} -> {dst} | {size}B"

    if sport and dport:
        base += f" | {sport} -> {dport}"

    return base


def format_alert(message, severity):
    if severity == "HIGH":
        return f"{RED}[HIGH] {message}{RESET}"
    elif severity == "MEDIUM":
        return f"{YELLOW}[MEDIUM] {message}{RESET}"
    else:
        return f"{GREEN}[LOW] {message}{RESET}"