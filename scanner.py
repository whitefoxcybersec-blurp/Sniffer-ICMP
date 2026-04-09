import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# Specify the subnet
SUBNET = '192.168.0.1/24'
MESSAGE = 'Scanner em Python'


class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))


# ICMP Header Structure
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


# Send UDP datagrams with our magic message
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        print(f"[*] Enviando pacotes UDP para {SUBNET}...")
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))
    print("[*] Pacotes UDP enviados!")


def get_local_ip():
    """Try to detect local IP automatically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class Scanner:
    def __init__(self, host):
        self.host = host
        self.hosts_up = set([f'{str(self.host)}*'])

        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print(f"[*] Modo promiscuous ativado (Windows)")
        else:
            print(f"[*] Socket RAW ICMP criado (Linux/Unix)")

    def sniff(self):
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[0:20])

                if ip_header.protocol == "ICMP" and ip_header.src_address != ipaddress.ip_address(self.host):
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)

                    # ICMP Destination Unreachable (Type 3, Code 3) with our magic message
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in self.hosts_up:
                                    self.hosts_up.add(str(ip_header.src_address))
                                    print(f'Host ativo: {tgt}')

        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        self.socket.close()

        print('\n[*] Interrompido pelo usuário')
        if len(self.hosts_up) > 1:  # More than just our own host
            print(f'\n[*] Resumo: Hosts ativos em {SUBNET}')
            for host in sorted(self.hosts_up):
                if host != f'{self.host}*':
                    print(f'  {host}')
        else:
            print(f'\n[*] Nenhum host ativo detectado em {SUBNET}')
        print('')


def main():
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        auto_ip = get_local_ip()
        print(f"[*] IP detectado automaticamente: {auto_ip}")
        choice = input(f"Deseja usar este IP? (S/n ou digite o IP desejado): ").strip()
        if choice.lower() == 'n' or not choice:
            host = input("Digite o IP da interface: ").strip()
        else:
            host = auto_ip

    # Validate IP
    try:
        ipaddress.ip_address(host)
    except:
        print(f"[!] IP inválido: {host}")
        sys.exit(1)

    print(f"[*] Escaneando {SUBNET} usando interface {host}...")

    # Start UDP sender in background
    sender_thread = threading.Thread(target=udp_sender)
    sender_thread.daemon = True
    sender_thread.start()

    # Start scanner
    scanner = Scanner(host)
    try:
        scanner.sniff()
    except:
        scanner.shutdown()


if __name__ == '__main__':
    main()