#!/usr/bin/env python3

from scapy.all import *
import argparse

def packet_callback(packet):

    print(f"[*] Packet Captured: {packet.summary()}")

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
    parser = argparse.ArgumentParser(description="Simple network sniffer using Scapy.")
    parser.add_argument("-i", "--interface", help="Specify the network interface to sniff on (e.g., eth0, wlan0).")
    parser.add_argument("-p", "--protocol", choices=['tcp', 'udp'], help="Filter packets by protocol (tcp or udp).")
    args = parser.parse_args()

    print("[*] Starting network sniffer...")
    print("[*] Press Ctrl+C to stop.")

    bpf_filter = args.protocol if args.protocol else ""

    try:
        if args.interface:
            print(f"[*] Sniffing on interface: {args.interface}")
            if bpf_filter:
                print(f"[*] Filtering for protocol: {bpf_filter.upper()}")
            sniff(prn=packet_callback, store=0, iface=args.interface, filter=bpf_filter)
        else:
            print("[*] No interface specified. Sniffing on default interface(s).")
            if bpf_filter:
                print(f"[*] Filtering for protocol: {bpf_filter.upper()}")
            sniff(prn=packet_callback, store=0, filter=bpf_filter)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
