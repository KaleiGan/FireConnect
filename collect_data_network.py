import time
from class_functions import calculate_entropy  # Assurez-vous que cette fonction existe et est correctement importée
from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import numpy as np
from collections import Counter
import threading
import csv
import os
import asyncio
import paho.mqtt.client as mqtt


current_attack_type = "Normal"  # Variable globale pour suivre le type d'attaque
active_attacks = Counter()  # Utilise un compteur pour suivre les types d'attaques actifs

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("attack/type")

def on_message(client, userdata, msg):
    global current_attack_type
    message = msg.payload.decode()
    attack_info = message.split(':')
    attack_type, attack_id, status = attack_info

    if 'start' in status:
        active_attacks[attack_id] = attack_type  # Enregistrer le type d'attaque sous son UUID
    elif 'end' in status and attack_id in active_attacks:
        del active_attacks[attack_id]  # Supprimer l'attaque de la liste active

    # Mettre à jour la chaîne des types d'attaques actifs basée sur les UUID uniques
    current_attack_types = set(active_attacks.values())
    current_attack_type = ', '.join(current_attack_types) if current_attack_types else "Normal"
    print(f"Updated attack types to: {current_attack_type}")



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
    collector = NetworkDataCollector(window_size=300, filename='network_data.csv')
    thread = threading.Thread(target=collector.start_capture)
    thread.start()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect("192.168.1.18", 1883)  # Assurez-vous que l'adresse IP est correcte
        client.loop_forever()
        while True:
            time.sleep(0.1)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.loop_stop()
        client.disconnect()
        thread.join()

if __name__ == "__main__":
    main()
