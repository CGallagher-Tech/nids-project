from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
import time
from detector import detect_port_scan, detect_icmp_flood
from logger import log_alert

conf.use_pcap = True

def extract_packet_info(packet):
    if IP not in packet:
        return None

    packet_info = {
        "timestamp": time.time(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None
    }

    if TCP in packet:
        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = packet[TCP].sport
        packet_info["dst_port"] = packet[TCP].dport

    elif UDP in packet:
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = packet[UDP].sport
        packet_info["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        packet_info["protocol"] = "ICMP"

    return packet_info

def process_packet(packet):
    try:
        packet_info = extract_packet_info(packet)

        if packet_info is None:
            return

        print(packet_info)

        alert = detect_port_scan(packet_info)
        if alert:
            print("\nALERT!")
            print(alert)
            log_alert(alert)
            print()

        alert = detect_icmp_flood(packet_info)
        if alert:
            print("\nALERT!")
            print(alert)
            log_alert(alert)
            print()

    except Exception as e:
        print(f"Packet processing error: {e}")

def start_sniffing(interface=None):
    print("Starting packet capture...")
    sniff(iface=interface, prn=process_packet, store=False, timeout=30)
    print("Packet capture finished.")