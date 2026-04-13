from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
import time

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
    packet_info = extract_packet_info(packet)

    if packet_info is None:
        return

    print(packet_info)

def start_sniffing(interface=None):
    print("Starting packet capture...")
    sniff(iface=interface, prn=process_packet, store=False, count=20)
    print("Packet capture finished.")