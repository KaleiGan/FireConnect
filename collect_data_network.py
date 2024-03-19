from class_functions import calculate_entropy  # Assurez-vous que cette fonction existe et est correctement importée
from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import numpy as np
from collections import Counter
import csv
import os

class NetworkDataCollector:
    def __init__(self, window_size=300, filename='network_data.csv'):
        self.window_size = window_size
        self.window_packets = []
        self.filename = filename
        self.ensure_file()

    def calculate_entropy(self, ip_list):
        count = Counter(ip_list)
        probabilities = [n / len(ip_list) for n in count.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy

    def ensure_file(self):
        # Crée le fichier CSV avec l'en-tête s'il n'existe pas
        if not os.path.isfile(self.filename):
            with open(self.filename, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
                writer.writeheader()

    def get_fieldnames(self):
        # Retourne la liste des noms des champs pour l'en-tête CSV
        return ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'length', 'icmp_type', 'tcp_flags',
                'entropy_src_ip', 'entropy_dst_ip', 'window_tx']

    def process_packet(self, packet):
        current_time = datetime.datetime.now()

        if IP not in packet:
            return

        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        length = len(packet)
        protocol = 'Other'
        src_port = dst_port = icmp_type = tcp_flags = None

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
            tcp_flags = str(packet[TCP].flags)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        elif ICMP in packet:
            protocol = 'ICMP'
            icmp_type = packet[ICMP].type

        self.window_packets.append((current_time, src_ip, dst_ip, length))
        self.window_packets = [(t, s, d, l) for (t, s, d, l) in self.window_packets if
                               (current_time - t).seconds < self.window_size]

        src_ips = [s for (_, s, _, _) in self.window_packets]
        dst_ips = [d for (_, _, d, _) in self.window_packets]
        total_tx = sum(l for (_, _, _, l) in self.window_packets)
        entropy_src = self.calculate_entropy(src_ips)
        entropy_dst = self.calculate_entropy(dst_ips)

        new_row = {
            'timestamp': current_time.strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': length,
            'icmp_type': icmp_type,
            'tcp_flags': tcp_flags,
            'entropy_src_ip': entropy_src,
            'entropy_dst_ip': entropy_dst,
            'window_tx': total_tx
        }

        # Sauvegarder immédiatement le nouveau paquet dans le fichier CSV
        with open(self.filename, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
            writer.writerow(new_row)

    def start_capture(self):
        sniff(prn=self.process_packet, store=False)

    # La méthode save_data n'est plus nécessaire dans ce contexte, mais vous pouvez la garder pour des tâches de nettoyage si besoin

# Utilisation dans une boucle infinie
collector = NetworkDataCollector()

try:
    while True:
        collector.start_capture()
except KeyboardInterrupt:
    print("Interruption détectée, arrêt...")
    # Ici, vous pouvez appeler collector.save_data() si vous avez besoin de sauvegarder les dernières données ou effectuer un nettoyage.

