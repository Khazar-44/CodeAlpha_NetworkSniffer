#!/usr/bin/env python3

from scapy.all import *

def packet_callback(packet):
    """
    This function will be called for every sniffed packet.
    You can analyze and process the packet here.
    """
    print(f"[*] Packet Captured: {packet.summary()}")

    # Example: Check for specific protocols
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Protocol: {ip_layer.proto}") # 6 for TCP, 17 for UDP, 1 for ICMP

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"  Source Port: {udp_layer.sport}")
        print(f"  Destination Port: {udp_layer.dport}")

    print("-" * 50)

def main():
    print("[*] Starting network sniffer...")
    print("[*] Press Ctrl+C to stop.")

    # sniff() function parameters:
    #   prn: callback function to apply to each packet
    #   count: number of packets to capture (0 for infinite)
    #   filter: BPF filter string (e.g., "tcp", "udp", "port 80", "host 192.168.1.1")
    #   iface: interface to sniff on (e.g., "eth0", "wlan0")

    # You might need to specify the interface if you have multiple.
    # To find your interfaces, use `ip a` or `ifconfig` in your terminal.
    # For example: sniff(prn=packet_callback, store=0, iface="eth0")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
