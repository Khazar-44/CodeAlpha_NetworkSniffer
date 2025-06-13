import socket
import struct

def sniff_http():
    host = socket.gethostbyname(socket.gethostname())  # or manually set IP

    # RAW socket for IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except:
        pass

    print("[*] Sniffing HTTP packets on", host)

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            if protocol == 6:  # TCP
                tcp_header = raw_data[20:40]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                dst_port = tcph[1]

                if 80 in (src_port, dst_port):  # HTTP
                    print(f"[HTTP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except:
            pass

if __name__ == "__main__":
    sniff_http()
