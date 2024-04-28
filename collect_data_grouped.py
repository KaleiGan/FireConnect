import time
import datetime
import numpy as np
from collections import Counter
import threading
import csv
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import paho.mqtt.client as mqtt
from class_functions import calculate_entropy  # Assurez-vous que cette fonction existe et est correctement importée

current_attack_type = "Normal"
active_attacks = Counter()  # Utilise un compteur pour suivre les types d'attaques actifs
is_connected = False


def on_connect(client, userdata, flags, rc, properties=None):
    global is_connected
    if rc == 0:
        is_connected = True
        print("Connecté au broker ! " + str(rc))
        client.subscribe("attack/type")
    else:
        print("Connection failed with result code " + str(rc))
        is_connected = False

def on_disconnect(client, userdata, flags, rc, properties=None):
    global is_connected
    is_connected = False
    print("Disconnected from MQTT broker.")

def manage_connection(client):
    while True:
        if not is_connected:
            print("Attempting to reconnect...")
            try:
                client.reconnect()
            except Exception as e:
                print(f"Reconnect failed: {e}")
        time.sleep(10)  # Vérifie l'état de la connexion toutes les 10 secondes


def on_message(client, userdata, msg):
    global current_attack_type
    message = msg.payload.decode()
    attack_info = message.split(':')
    attack_type, attack_id, status = attack_info

    if 'start' in status:
        active_attacks[attack_id] = attack_type  # Enregistrer le type d'attaque sous son UUID
    elif 'end' in status and attack_id in active_attacks:
        del active_attacks[attack_id]  # Supprimer l'attaque de la liste active
        time.sleep(2)

    # Mettre à jour la chaîne des types d'attaques actifs basée sur les UUID uniques
    current_attack_types = set(active_attacks.values())
    current_attack_type = ', '.join(current_attack_types) if current_attack_types else "Normal"
    print(f"Updated attack types to: {current_attack_type}")
    print(f"{datetime.datetime.now().hour}:{datetime.datetime.now().minute}")


class NetworkDataCollector:
    def __init__(self, window_size=4, filename='network_data_grouped.csv'):
        self.window_size = window_size
        self.window_packets = []
        self.filename = filename
        self.ensure_file()
        self.last_write_time = datetime.datetime.now()
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

    def ensure_file(self):
        if not os.path.isfile(self.filename):
            with open(self.filename, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
                writer.writeheader()

    def get_fieldnames(self):
        return ['timestamp', 'entropy_src_ip', 'entropy_dst_ip', 'window_tx',
                'median_packet_size', 'mean_packet_size', 'std_dev_packet_size',
                'packet_frequency', 'unique_ip', 'tcp_count', 'udp_count', 'icmp_count', 'type_attack']

    def calculate_in_out_ratio(self):
        # Calcul du ratio des paquets entrants et sortants
        input_packets = sum(1 for (_, src, _, _) in self.window_packets if src == 'local_IP')
        output_packets = sum(1 for (_, _, dst, _) in self.window_packets if dst == 'local_IP')
        return input_packets / output_packets if output_packets else 0

    def unique_ip_count(self):
        src_ips = [src for (_, src, _, _) in self.window_packets]
        return len(src_ips)

    def calculate_active_window_duration(self):
        # Calcul de la durée d'activité réelle de la fenêtre
        if self.window_packets:
            start_time = min(t for (t, _, _, _) in self.window_packets)
            end_time = max(t for (t, _, _, _) in self.window_packets)
            return (end_time - start_time).total_seconds()
        return 0

    def write_window_statistics(self):
        if not self.window_packets:
            return  # Si aucune donnée, ne rien faire

        current_time = datetime.datetime.now()
        src_ips = [s for (_, s, _, _) in self.window_packets]
        dst_ips = [d for (_, _, d, _) in self.window_packets]
        total_tx = sum(l for (_, _, _, l) in self.window_packets)
        entropy_src = calculate_entropy(src_ips)
        entropy_dst = calculate_entropy(dst_ips)
        median_packet_size, mean_packet_size, std_dev_packet_size = self.packet_statistics(self.window_packets)
        packet_frequency = self.calculate_packet_frequency()


        new_row = {
            'timestamp': current_time.strftime("%Y-%m-%d %H:%M:%S"),
            'entropy_src_ip': entropy_src,
            'entropy_dst_ip': entropy_dst,
            'window_tx': total_tx,
            'median_packet_size': median_packet_size,
            'mean_packet_size': mean_packet_size,
            'std_dev_packet_size': std_dev_packet_size,
            'unique_ip': self.unique_ip_count(),
            'packet_frequency': packet_frequency,
            'tcp_count': self.tcp_count,
            'udp_count': self.udp_count,
            'icmp_count': self.icmp_count,
            'type_attack': current_attack_type
        }

        with open(self.filename, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
            writer.writerow(new_row)

        self.window_packets = []  # Clear the current window packets
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

    def packet_statistics(self, packets):
        lengths = [l for (_, _, _, l) in packets]
        if not lengths:
            return 0, 0, 0
        return np.median(lengths), np.mean(lengths), np.std(lengths)

    def calculate_packet_frequency(self):
        if not self.window_packets:
            return 0
        start_time = min(t for (t, _, _, _) in self.window_packets)
        end_time = max(t for (t, _, _, _) in self.window_packets)
        duration = (end_time - start_time).total_seconds()
        if duration > 0:
            return len(self.window_packets) / duration
        return 0

    def process_packet(self, packet):
        current_time = datetime.datetime.now()

        if IP not in packet:
            return

        src_ip = packet[IP].src
        if TCP in packet:
            self.tcp_count += 1
        elif UDP in packet:
            self.udp_count += 1
        elif ICMP in packet:
            self.icmp_count += 1

        dst_ip = packet[IP].dst
        length = len(packet)

        self.window_packets.append((current_time, src_ip, dst_ip, length))
        if (current_time - self.last_write_time).total_seconds() >= self.window_size:
            self.write_window_statistics()
            self.last_write_time = current_time

    def start_capture(self):
        sniff(prn=self.process_packet, store=False)


def main():
    collector = NetworkDataCollector(window_size=4, filename='network_data_grouped.csv')
    thread = threading.Thread(target=collector.start_capture)
    thread.start()
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    try:
        client.connect("192.168.3.109", 1883)
    except Exception as e:
        print(f"An error occurred: {e}")
        
    thread2 = threading.Thread(target=manage_connection, args=(client,))
    thread2.start()
    client.loop_forever()

if __name__ == "__main__":
    main()
