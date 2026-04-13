import time
import ipaddress
from collections import defaultdict

LOCAL_SUBNET = ipaddress.ip_network("10.222.3.0/24")

# Store activity by source IP
scan_tracker = defaultdict(list)

# Detection settings
PORT_SCAN_THRESHOLD = 15   # number of different ports
TIME_WINDOW = 5            # seconds

# Track already alerted IPs
icmp_alerted = set()

def detect_port_scan(packet_info):
    # Only care about TCP and UDP packets with destination ports
    if packet_info["protocol"] not in ["TCP", "UDP"]:
        return None

    src_ip = packet_info["src_ip"]
    dst_port = packet_info["dst_port"]
    current_time = packet_info["timestamp"]

    # Add this packet activity
    scan_tracker[src_ip].append((dst_port, current_time))

    # Remove old entries outside the time window
    scan_tracker[src_ip] = [
        (port, ts) for port, ts in scan_tracker[src_ip]
        if current_time - ts <= TIME_WINDOW
    ]

    # Count unique destination ports
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

# ICMP detection settings
ICMP_THRESHOLD = 5   # number of packets
ICMP_TIME_WINDOW = 10  # seconds

def detect_icmp_flood(packet_info):
    if packet_info["protocol"] != "ICMP":
        return None

    src_ip = packet_info["src_ip"]

    if ipaddress.ip_address(src_ip) not in LOCAL_SUBNET:
        return None

    current_time = packet_info["timestamp"]

    # Add timestamp
    icmp_tracker[src_ip].append(current_time)

    # Remove old entries
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

    # Reset alert if activity drops
    if len(icmp_tracker[src_ip]) < ICMP_THRESHOLD:
        if src_ip in icmp_alerted:
            icmp_alerted.remove(src_ip)

    return None