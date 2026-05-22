import json
from config import REPORT_FILE
from core.stats import get_stats

def generate_report():
    report = {
        "stats": get_stats(),
        "analysis": "Basic anomaly detection applied (traffic + port behavior)"
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[✔] Report saved to {REPORT_FILE}")