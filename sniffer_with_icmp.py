import ipaddress
import os
import socket
import struct
import sys
from datetime import datetime
from collections import Counter


# Estrutura do Cabeçalho IP (20 bytes)
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


# Estrutura do Cabeçalho ICMP
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


# Estrutura básica para TCP
class TCP:
    def __init__(self, buff):
        header = struct.unpack('!HHLLBBHHH', buff[:20])
        self.src_port = header[0]
        self.dst_port = header[1]


# Estrutura básica para UDP
class UDP:
    def __init__(self, buff):
        header = struct.unpack('!HHHH', buff[:8])
        self.src_port = header[0]
        self.dst_port = header[1]


def get_protocol_info(ip_header, raw_buffer):
    offset = ip_header.ihl * 4
    proto_data = raw_buffer[offset:]

    info = ""
    if ip_header.protocol == "ICMP":
        icmp = ICMP(proto_data[:8])
        info = f" [ICMP Type: {icmp.type} Code: {icmp.code}]"
    elif ip_header.protocol == "TCP":
        tcp = TCP(proto_data)
        info = f" [TCP Port: {tcp.src_port} -> {tcp.dst_port}]"
    elif ip_header.protocol == "UDP":
        udp = UDP(proto_data)
        info = f" [UDP Port: {udp.src_port} -> {udp.dst_port}]"

    return info


def print_report(stats, start_time):
    end_time = datetime.now()
    duration = end_time - start_time

    print("\n" + "=" * 50)
    print("           RELATÓRIO FINAL DE CAPTURA")
    print("=" * 50)
    print(f"Início: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Fim:    {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duração: {duration}")
    print("-" * 50)
    print(f"Total de Pacotes Capturados: {stats['total']}")
    print("-" * 50)
    print("Distribuição por Protocolo:")
    for proto, count in stats['protocols'].items():
        percent = (count / stats['total']) * 100 if stats['total'] > 0 else 0
        print(f"  - {proto:6}: {count:4} ({percent:5.1f}%)")

    print("-" * 50)
    print("Top 5 IPs de Origem:")
    for ip, count in stats['src_ips'].most_common(5):
        print(f"  - {str(ip):15}: {count} pacotes")

    print("-" * 50)
    print("Top 5 IPs de Destino:")
    for ip, count in stats['dst_ips'].most_common(5):
        print(f"  - {str(ip):15}: {count} pacotes")
    print("=" * 50 + "\n")


def get_local_ip():
    """Tenta detectar o IP local automaticamente."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def sniff(host, log_file=None):
    # Estatísticas para o relatório
    stats = {
        'total': 0,
        'protocols': Counter(),
        'src_ips': Counter(),
        'dst_ips': Counter()
    }
    start_time = datetime.now()

    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print(f"[*] Sniffer iniciado em {host}...")
        print("[*] Pressione Ctrl+C para parar e ver o relatório.")
        if log_file:
            print(f"[*] Salvando logs em: {log_file}")

        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            ip_header = IP(raw_buffer[0:20])

            # Atualizar estatísticas
            stats['total'] += 1
            stats['protocols'][ip_header.protocol] += 1
            stats['src_ips'][ip_header.src_address] += 1
            stats['dst_ips'][ip_header.dst_address] += 1

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            proto_info = get_protocol_info(ip_header, raw_buffer)

            output = f"[{timestamp}] {ip_header.protocol:4} | {ip_header.src_address} -> {ip_header.dst_address}{proto_info}"
            print(output)

            if log_file:
                with open(log_file, "a") as f:
                    f.write(output + "\n")

    except KeyboardInterrupt:
        print("\n[*] Interrompido pelo usuário.")
        if stats['total'] > 0:
            print_report(stats, start_time)
        else:
            print("[!] Nenhum pacote capturado.")

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except PermissionError:
        print("[!] Erro: Permissões insuficientes. Execute como Administrador/Root.")
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")


if __name__ == '__main__':
    target_host = None
    log_path = None

    # Se o usuário passou argumentos via linha de comando
    if len(sys.argv) >= 2:
        target_host = sys.argv[1]
        if len(sys.argv) > 2:
            log_path = sys.argv[2]
    else:
        # Se não passou argumentos, tenta detectar automaticamente
        auto_ip = get_local_ip()
        print(f"[*] IP detectado automaticamente: {auto_ip}")
        choice = input(f"Deseja usar este IP? (S/n ou digite o IP desejado): ").strip()

        if choice.lower() == 's' or choice == '':
            target_host = auto_ip
        elif choice.lower() == 'n':
            target_host = input("Digite o IP local para o sniffer: ").strip()
        else:
            target_host = choice  # Se o usuário digitou um IP diretamente

    if target_host:
        sniff(target_host, log_path)
    else:
        print("[!] Erro: Nenhum IP especificado.")
        sys.exit(1)
