# ISH-
PROJECT REPOSITORY OF INFORMATION SECURITY HACKING 

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    """Callback function to process captured packets."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

         # Map protocol numbers to names
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(proto, "Other")

        print(f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol_name}")

def main():
    print("=== Packet Sniffer ===")
    print("Listening for packets... Press Ctrl+C to stop.")
    try:
        # Start sniffing packets
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")

if _name_ == "_main_":
    main()
