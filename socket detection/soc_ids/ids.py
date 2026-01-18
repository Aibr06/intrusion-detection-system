import psutil
import time
from collections import defaultdict
from datetime import datetime

# Track connections per IP
connection_count = defaultdict(int)
blocked_ips = set()

ALERT_THRESHOLD = 10   # connections per minute

def log_alert(message):
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now()} ALERT: {message}\n")

def log_attacker(ip):
    with open("attackers.log", "a") as f:
        f.write(f"{datetime.now()} ATTACKER: {ip}\n")

print("SOC Intrusion Detection System Running...")
print("Monitoring network connections...\n")

while True:
    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        time.sleep(5)
        continue

    for conn in connections:
        if conn.raddr:
            ip = conn.raddr.ip
            connection_count[ip] += 1

            # Detect port scanning / brute force
            if connection_count[ip] > ALERT_THRESHOLD and ip not in blocked_ips:
                alert_msg = f"Suspicious activity detected from IP {ip}"
                print(alert_msg)

                log_alert(alert_msg)
                log_attacker(ip)

                blocked_ips.add(ip)

    time.sleep(60)

