# CodeAlpha - Task 1: Basic Network Sniffer
# Author: Akshay Rajendra Sonwane 

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Packet Captured at {timestamp}")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if proto == 6:
            print("Protocol: TCP")
        elif proto == 17:
            print("Protocol: UDP")
        elif proto == 1:
            print("Protocol: ICMP")
        else:
            print(f"Protocol: Other ({proto})")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            print(f"Payload (first 50 bytes): {payload[:50]}")
        else:
            print("No payload data.")
    else:
        print("Non-IP Packet Type Captured")

print("Starting network sniffer... Press CTRL+C to stop.\n")
sniff(prn=packet_callback, count=0)
