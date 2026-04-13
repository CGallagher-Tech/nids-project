import json
import os
from datetime import datetime

ALERTS_FILE = "alerts.json"

def log_alert(alert):
    log_entry = {
        "time_logged": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": alert["alert_type"],
        "source_ip": alert["source_ip"],
        "details": alert["details"],
        "timestamp": alert["timestamp"]
    }

    existing_alerts = []

    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r") as file:
                content = file.read().strip()
                if content:
                    existing_alerts = json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError):
            existing_alerts = []

    existing_alerts.append(log_entry)

    with open(ALERTS_FILE, "w") as file:
        json.dump(existing_alerts, file, indent=4)

    print(f"Alert logged to {ALERTS_FILE}")