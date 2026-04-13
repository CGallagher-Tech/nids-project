import time
import json
import ipaddress
import socket
from collections import defaultdict

# Load config
with open("config.json", "r") as f:
    config = json.load(f)

PORT_SCAN_THRESHOLD = config["port_scan"]["threshold"]
TIME_WINDOW = config["port_scan"]["time_window"]

ICMP_THRESHOLD = config["icmp_flood"]["threshold"]
ICMP_TIME_WINDOW = config["icmp_flood"]["time_window"]

def get_local_subnet():
    try:
        # Connect to an external address to determine the local IP in use
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume a /24 subnet from the local IP
        subnet = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        print(f"Auto-detected local subnet: {subnet}")
        return subnet
    except Exception as e:
        print(f"Could not auto-detect subnet: {e}")
        return None

LOCAL_SUBNET = get_local_subnet()

# Store activity by source IP
scan_tracker = defaultdict(list)

# Track already alerted IPs
icmp_alerted = set()

def detect_port_scan(packet_info):
    if packet_info["protocol"] not in ["TCP", "UDP"]:
        return None

    src_ip = packet_info["src_ip"]
    dst_port = packet_info["dst_port"]
    current_time = packet_info["timestamp"]

    scan_tracker[src_ip].append((dst_port, current_time))

    scan_tracker[src_ip] = [
        (port, ts) for port, ts in scan_tracker[src_ip]
        if current_time - ts <= TIME_WINDOW
    ]

    unique_ports = {port for port, ts in scan_tracker[src_ip]}

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        return {
            "alert_type": "Possible Port Scan",
            "source_ip": src_ip,
            "details": f"{src_ip} contacted {len(unique_ports)} different ports in {TIME_WINDOW} seconds",
            "timestamp": current_time
        }

    return None

# Track ICMP activity per source IP
icmp_tracker = defaultdict(list)

def detect_icmp_flood(packet_info):
    if packet_info["protocol"] != "ICMP":
        return None

    src_ip = packet_info["src_ip"]

    # Skip if subnet detection failed or src is not on local network
    if LOCAL_SUBNET is None or ipaddress.ip_address(src_ip) not in LOCAL_SUBNET:
        return None

    current_time = packet_info["timestamp"]

    icmp_tracker[src_ip].append(current_time)

    icmp_tracker[src_ip] = [
        ts for ts in icmp_tracker[src_ip]
        if current_time - ts <= ICMP_TIME_WINDOW
    ]

    if len(icmp_tracker[src_ip]) >= ICMP_THRESHOLD:
        if src_ip not in icmp_alerted:
            icmp_alerted.add(src_ip)
            return {
                "alert_type": "Possible ICMP Flood",
                "source_ip": src_ip,
                "details": f"{src_ip} sent {len(icmp_tracker[src_ip])} ICMP packets in {ICMP_TIME_WINDOW} seconds",
                "timestamp": current_time
            }

    if len(icmp_tracker[src_ip]) < ICMP_THRESHOLD:
        if src_ip in icmp_alerted:
            icmp_alerted.remove(src_ip)

    return None