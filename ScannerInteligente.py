import ipaddress
import os
import socket
import struct
import sys
import threading
import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from collections import defaultdict
import json

SUBNET = '192.168.0.1/24'
MAGIC_MESSAGE = 'ScannerML-Powered'


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


class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


class DeviceProfiler:
    """Perfilador de dispositivos usando Machine Learning"""

    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.label_encoders = {}
        self.device_history = defaultdict(list)
        self.is_trained = False

        # Features para classificação ML
        self.feature_names = [
            'response_time_ms', 'packet_size', 'ttl', 'udp_port',
            'response_count', 'avg_interval', 'variance_interval'
        ]

    def extract_features(self, host_data):
        """Extrai 7 features do histórico do host"""
        if len(host_data) < 2:
            return None

        times = [d['timestamp'] for d in host_data]
        sizes = [d['packet_size'] for d in host_data]

        try:
            return {
                'response_time_ms': np.mean([t['rtt'] for t in times[-5:]]),
                'packet_size': np.mean(sizes[-5:]),
                'ttl': np.mean([t['ttl'] for t in times[-5:]]),
                'udp_port': times[-1]['udp_port'],
                'response_count': len(host_data),
                'avg_interval': np.mean(np.diff([t['timestamp'] for t in times])),
                'variance_interval': np.var(np.diff([t['timestamp'] for t in times]))
            }
        except:
            return None

    def train_model(self, training_data_path='device_fingerprints.json'):
        """Treina modelo com fingerprints de dispositivos conhecidos"""
        try:
            with open(training_data_path, 'r') as f:
                data = json.load(f)

            X, y = [], []
            for device_type, samples in data.items():
                for sample in samples:
                    features = np.array([sample.get(f, 0) for f in self.feature_names])
                    X.append(features)
                    y.append(device_type)

            if len(X) > 10:
                self.label_encoders['device'] = LabelEncoder()
                y_encoded = self.label_encoders['device'].fit_transform(y)

                self.model.fit(X, y_encoded)
                self.is_trained = True
                print(f"[🤖 ML] Modelo treinado com {len(X)} amostras de {len(set(y))} tipos de dispositivos")
                return True
            return False

        except FileNotFoundError:
            return self._create_sample_dataset(training_data_path)

    def _create_sample_dataset(self, path):
        """Cria dataset de treinamento com fingerprints realistas"""
        sample_data = {
            'Router': [
                {'response_time_ms': 2.1, 'packet_size': 84, 'ttl': 64, 'udp_port': 65212, 'response_count': 5,
                 'avg_interval': 0.1, 'variance_interval': 0.01},
                {'response_time_ms': 1.8, 'packet_size': 84, 'ttl': 64, 'udp_port': 65212, 'response_count': 3,
                 'avg_interval': 0.15, 'variance_interval': 0.02},
                {'response_time_ms': 2.5, 'packet_size': 80, 'ttl': 64, 'udp_port': 65212, 'response_count': 4,
                 'avg_interval': 0.12, 'variance_interval': 0.015}
            ],
            'WindowsPC': [
                {'response_time_ms': 5.2, 'packet_size': 92, 'ttl': 128, 'udp_port': 65212, 'response_count': 8,
                 'avg_interval': 0.2, 'variance_interval': 0.05},
                {'response_time_ms': 6.1, 'packet_size': 88, 'ttl': 128, 'udp_port': 65212, 'response_count': 6,
                 'avg_interval': 0.25, 'variance_interval': 0.08},
                {'response_time_ms': 4.8, 'packet_size': 90, 'ttl': 128, 'udp_port': 65212, 'response_count': 7,
                 'avg_interval': 0.22, 'variance_interval': 0.06}
            ],
            'LinuxServer': [
                {'response_time_ms': 3.5, 'packet_size': 76, 'ttl': 64, 'udp_port': 65212, 'response_count': 12,
                 'avg_interval': 0.08, 'variance_interval': 0.03},
                {'response_time_ms': 3.2, 'packet_size': 80, 'ttl': 64, 'udp_port': 65212, 'response_count': 15,
                 'avg_interval': 0.07, 'variance_interval': 0.02},
                {'response_time_ms': 3.8, 'packet_size': 78, 'ttl': 64, 'udp_port': 65212, 'response_count': 10,
                 'avg_interval': 0.09, 'variance_interval': 0.04}
            ],
            'IoT': [
                {'response_time_ms': 15.0, 'packet_size': 56, 'ttl': 255, 'udp_port': 65212, 'response_count': 2,
                 'avg_interval': 1.0, 'variance_interval': 0.5},
                {'response_time_ms': 18.2, 'packet_size': 60, 'ttl': 255, 'udp_port': 65212, 'response_count': 1,
                 'avg_interval': 2.0, 'variance_interval': 1.2}
            ],
            'MacOS': [
                {'response_time_ms': 4.2, 'packet_size': 84, 'ttl': 64, 'udp_port': 65212, 'response_count': 5,
                 'avg_interval': 0.18, 'variance_interval': 0.04}
            ]
        }

        with open(path, 'w') as f:
            json.dump(sample_data, f, indent=2)
        print(f"[🤖 ML] Dataset de exemplo criado: {path}")
        return False

    def predict_device(self, host_ip):
        """Prediz tipo de dispositivo com confiança"""
        host_data = self.device_history[host_ip]
        features = self.extract_features(host_data)

        if features and self.is_trained:
            feature_vector = np.array([features[f] for f in self.feature_names]).reshape(1, -1)
            pred = self.model.predict(feature_vector)[0]

            if 'device' in self.label_encoders:
                device_type = self.label_encoders['device'].inverse_transform([pred])[0]
                confidence = self.model.predict_proba(feature_vector).max()
                return device_type, confidence
        return "Unknown", 0.0


class MLScanner:
    """Scanner de rede com Machine Learning para identificação de dispositivos"""

    def __init__(self, host):
        self.host = host
        self.profiler = DeviceProfiler()
        self.profiler.train_model()
        self.hosts_up = {}
        self.socket = self._create_raw_socket()
        print(f"[🤖 ML] Scanner inicializado na interface {host}")

    def _create_raw_socket(self):
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sock.bind((self.host, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print("[*] Modo promiscuous ativado (Windows)")
        else:
            print("[*] Socket RAW ICMP criado (Linux/Unix)")
        return sock

    def sniff(self):
        print("[🤖 ML] Aguardando respostas ICMP... (Ctrl+C para parar)")
        try:
            while True:
                start_time = time.time()
                raw_buffer = self.socket.recvfrom(65535)[0]
                rtt = (time.time() - start_time) * 1000  # ms

                ip_header = IP(raw_buffer[0:20])

                if self._is_valid_response(ip_header, raw_buffer):
                    host_ip = str(ip_header.src_address)
                    self._update_host_profile(host_ip, ip_header, rtt, raw_buffer)

        except KeyboardInterrupt:
            self.shutdown()

    def _is_valid_response(self, ip_header, raw_buffer):
        return (ip_header.protocol == "ICMP" and
                ip_header.src_address != ipaddress.ip_address(self.host) and
                ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET) and
                raw_buffer[-len(MAGIC_MESSAGE):] == bytes(MAGIC_MESSAGE, 'utf8'))

    def _update_host_profile(self, host_ip, ip_header, rtt, raw_buffer):
        now = time.time()

        if host_ip not in self.hosts_up:
            self.hosts_up[host_ip] = {
                'first_seen': now,
                'responses': [],
                'device_type': 'Unknown',
                'confidence': 0.0
            }

        profile = {
            'timestamp': now,
            'rtt': rtt,
            'ttl': ip_header.ttl,
            'packet_size': len(raw_buffer),
            'udp_port': 65212
        }

        self.hosts_up[host_ip]['responses'].append(profile)
        self.profiler.device_history[host_ip].append(profile)

        # Predição ML a cada 3 respostas
        if len(self.hosts_up[host_ip]['responses']) % 3 == 0:
            device_type, confidence = self.profiler.predict_device(host_ip)
            self.hosts_up[host_ip]['device_type'] = device_type
            self.hosts_up[host_ip]['confidence'] = confidence

            print(f"🖥️  {host_ip:<15} | {device_type:<12} ({confidence:.1%}) | RTT: {rtt:.1f}ms")

    def shutdown(self):
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        self.socket.close()
        self._print_ml_summary()

    def _print_ml_summary(self):
        print('\n' + '=' * 90)
        print("🤖 RESUMO COMPLETO - SCANNER ML-POWERED")
        print('=' * 90)
        print(
            f"{'IP':<16} {'TIPO DISPOSITIVO':<15} {'CONF':<6} {'RTT(ms)':<8} {'TTL':<5} {'RESP':<5} {'PRIMEIRA VISTA'}")
        print('-' * 90)

        if self.hosts_up:
            for host_ip, data in sorted(self.hosts_up.items()):
                rtt_avg = np.mean([r['rtt'] for r in data['responses'][-5:]]) if data['responses'] else 0
                ttl_avg = np.mean([r['ttl'] for r in data['responses'][-5:]]) if data['responses'] else 0
                print(f"{host_ip:<16} {data['device_type']:<15} {data['confidence']:.0%:<6} "
                      f"{rtt_avg:<8.1f} {ttl_avg:<5.0f} {len(data['responses']):<5} "
                      f"{time.strftime('%H:%M:%S', time.localtime(data['first_seen']))}")
        else:
            print("❌ Nenhum host ativo detectado na rede!")

        print('=' * 90)
        print("👋 Scanner finalizado!")


def udp_sender():
    """Envia pacotes UDP de descoberta para toda a sub-rede"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        print(f"[📡] Enviando pacotes UDP de descoberta para {SUBNET}...")
        hosts_count = 0
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MAGIC_MESSAGE, 'utf8'), (str(ip), 65212))
            hosts_count += 1
            if hosts_count % 50 == 0:
                print(f"    {hosts_count} hosts enviados...")
        print(f"[✅] {hosts_count} pacotes UDP enviados! Aguardando respostas...")


def get_local_ip():
    """Detecta IP local automaticamente"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    print("🚀 SCANNER ML-POWERED v2.0")
    print("=" * 50)

    # Seleção de interface
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        auto_ip = get_local_ip()
        print(f"[🔍] IP detectado automaticamente: {auto_ip}")
        choice = input(f"Usar este IP? [S/n] ou digite IP: ").strip().lower()
        host = auto_ip if choice in ['', 's', 'sim'] else input("IP da interface: ").strip()

    # Validação
    try:
        ipaddress.ip_address(host)
        print(f"[✅] Interface válida: {host}")
    except:
        print(f"[❌] IP inválido: {host}")
        sys.exit(1)

    # Inicia scan
    print(f"\n[🎯] Escaneando {SUBNET} com Machine Learning...")

    # Thread UDP em background
    sender_thread = threading.Thread(target=udp_sender)
    sender_thread.daemon = True
    sender_thread.start()

    # Scanner ML
    time.sleep(1)  # Aguarda UDP iniciar
    scanner = MLScanner(host)
    scanner.sniff()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Até logo!")
    except Exception as e:
        print(f"[❌] Erro: {e}")