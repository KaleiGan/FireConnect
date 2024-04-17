from class_functions import calculate_entropy  # Assurez-vous que cette fonction existe et est correctement importée
from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import numpy as np
from collections import Counter
import threading
import csv
import os
import asyncio
import websockets

current_attack_type = "Normal"  # Variable globale pour suivre le type d'attaque actuel

async def update_attack_type(websocket, path):
    global current_attack_type
    async for message in websocket:
        if '_end' in message:
            current_attack_type = "Normal"
        else:
            current_attack_type = message.replace('_start', '')
        print(f"Updated attack type to: {current_attack_type}")

async def start_websocket_server():
    async with websockets.serve(update_attack_type, "localhost", 8765):
        await asyncio.Future()  # Run indefinitely


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
                'entropy_src_ip', 'entropy_dst_ip', 'window_tx', 'type_attack']

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
            'window_tx': total_tx,
            'type_attack': current_attack_type  # Ajouter le type d'attaque actuel

        }

        # Sauvegarder immédiatement le nouveau paquet dans le fichier CSV
        with open(self.filename, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
            writer.writerow(new_row)

    def start_capture(self):
        sniff(prn=self.process_packet, store=False)

    # La méthode save_data n'est plus nécessaire dans ce contexte, mais vous pouvez la garder pour des tâches de nettoyage si besoin

# Fonction pour démarrer la capture dans un thread séparé
def start_sniffing(collector):
    collector.start_capture()

# Fonction principale pour démarrer le serveur et la capture
def main():
    collector = NetworkDataCollector()
    thread = threading.Thread(target=start_sniffing, args=(collector,))
    thread.start()  # Démarrer la capture dans un thread séparé

    loop = asyncio.get_event_loop()
    ws_server = loop.create_task(start_websocket_server())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
    finally:
        ws_server.cancel()
        loop.run_until_complete(ws_server)
        loop.close()
        thread.join()  # Assurez-vous que le thread de capture termine proprement

if __name__ == "__main__":
    main()
