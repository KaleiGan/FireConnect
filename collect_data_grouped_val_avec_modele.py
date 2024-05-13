import time
import datetime
import numpy as np
import pandas as pd
from collections import Counter
import threading
import csv
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import paho.mqtt.client as mqtt
from class_functions import calculate_entropy
import smtplib
import joblib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess 

active_attacks = Counter()  # Compteur pour suivre les attaques actives
is_connected = False  # Variable de statut de connexion

# Charger les objets pour utilisation du modele
model_path = 'val/random_forest_model_10k.pkl'
scaler_path = 'val/scaler.pkl'
encoder_path = 'val/encoder.pkl'
rf_model = joblib.load(model_path)
scaler = joblib.load(scaler_path)
encoder = joblib.load(encoder_path)

# Méthode évenement pour la connexion au broker MQTT
def on_connect(client, userdata, flags, rc, properties=None):
    global is_connected
    if rc == 0:
        is_connected = True
        print("Connecté au broker MQTT avec succès ! " + str(rc))
        client.subscribe("attack/type")
    else:
        print("Échec de la connexion au broker MQTT " + str(rc))
        is_connected = False

# Méthode d'envoi d'emails en cas d'alerte attaque        
def send_email(subject, body):
    sender_email = "val_project_lab@gmail.com"
    receiver_email = "valentin.nguyen@gmail.com"
    password = "mot_de_passe_valentin"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP('smtp.example.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()
 
# Méthode d'utilisation Playbook Ansible    
def trigger_ansible_playbook(ip_list):
    playbook_path = 'ansible/playbook_attack.yml'
    inventory_path = 'ansible/inventaire'

    # Appel du Playbook
    try:
        subprocess.run(['ansible-playbook', playbook_path, '-i', inventory_path, '--extra-vars', f"list_of_suspicious_ips={ip_list}"], check=True)
        print("Playbook exécuté")
    except subprocess.CalledProcessError as e:
        print("Erreur lors de l'execution du playbook:", e)

# Méthode évenement en cas de deconnexion du broker MQTT
def on_disconnect(client, userdata, flags, rc, properties=None):
    global is_connected
    is_connected = False
    print("Déconnexion du broker MQTT.")

# Méthode évenement pour la reconnexion au broker MQTT
def manage_connection(client):
    while True:
        if not is_connected:
            print("Attente de connexion...")
            try:
                client.reconnect()
            except Exception as e:
                print(f"Echec de reconnexion : {e}")
        time.sleep(10)

# Méthode évenement lors de la réception de messages MQTT
def on_message(client, userdata, msg):
    global current_attack_type
    message = msg.payload.decode()
    attack_info = message.split(':')
    attack_type, attack_id, status = attack_info

    if 'start' in status:
        active_attacks[attack_id] = attack_type
    elif 'end' in status and attack_id in active_attacks:
        del active_attacks[attack_id]

    current_attack_types = set(active_attacks.values())
    current_attack_type = ', '.join(current_attack_types) if current_attack_types else "Normal"
    print(f"Updated attack types to: {current_attack_type}")
    print(f"{datetime.datetime.now().hour}:{datetime.datetime.now().minute}")

class NetworkDataCollector:
    # Classe pour collecter et analyser les données réseau
    def __init__(self, window_size=4, filename='network_data_grouped_model.csv'):
        self.window_size = window_size  # Taille de la fenêtre temporelle pour l'analyse
        self.window_packets = []  # Stocke les paquets dans la fenêtre actuelle
        self.filename = filename  # Nom du fichier pour stocker les données
        self.ensure_file()  # Vérifie que le fichier existe, sinon le crée
        self.last_write_time = datetime.datetime.now()
        self.tcp_count = 0  # Compte les paquets TCP
        self.udp_count = 0  # Compte les paquets UDP
        self.icmp_count = 0  # Compte les paquets 
        self.last_normal_ips = set()  # Ensemble pour stocker les adresses IP du dernier lot normal
        self.current_ips = set()  # Ensemble pour stocker les adresses IP du lot courant

    def ensure_file(self):
        if not os.path.isfile(self.filename):
            with open(self.filename, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
                writer.writeheader()

    def get_fieldnames(self):
        # Retourne les noms des colonnes pour le fichier CSV
        return ['timestamp', 'entropy_src_ip', 'entropy_dst_ip', 'window_tx',
                'median_packet_size', 'mean_packet_size', 'std_dev_packet_size',
                'packet_frequency', 'unique_ip', 'tcp_count', 'udp_count', 'icmp_count', 'type_attack']

    def calculate_in_out_ratio(self):
        # Calcul du ratio des paquets entrants et sortants
        input_packets = sum(1 for (_, src, _, _) in self.window_packets if src == 'local_IP')
        output_packets = sum(1 for (_, _, dst, _) in self.window_packets if dst == 'local_IP')
        return input_packets / output_packets if output_packets else 0

    def unique_ip_count(self):
        # Retourne le nombre d'adresses IP uniques
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
        
        # Prépareration des données pour le modèle
        features = np.array([entropy_src, entropy_dst, total_tx, median_packet_size, mean_packet_size, std_dev_packet_size, packet_frequency, self.unique_ip_count(), self.tcp_count, self.udp_count, self.icmp_count]).reshape(1, -1)
        feature_names = ['entropy_src_ip', 'entropy_dst_ip', 'window_tx', 'median_packet_size', 'mean_packet_size', 'std_dev_packet_size', 'packet_frequency', 'unique_ip_count', 'tcp_count', 'udp_count', 'icmp_count']
        # Conversion des features en DataFrame
        features_df = pd.DataFrame(features, columns=feature_names)
        features_scaled = scaler.transform(features_df)
        attack_type_encoded = rf_model.predict(features_scaled)
        
        attack_type = encoder.inverse_transform([attack_type_encoded])[0]
        
        # Gérer les adresses IP en fonction du type d'attaque détecté
        if attack_type == "Normal":
            self.last_normal_ips = self.current_ips.copy()  # Mettre à jour le dernier lot normal
            print(f"Trafic {attack_type}")
        else:
            suspect_ips = self.current_ips - self.last_normal_ips  # Soustraire les IP normales des suspectes
            print(f"Attaque detecté : {attack_type}")
            if suspect_ips:  # Si des adresses suspectes restent
                pass
                # trigger_ansible_playbook(suspect_ips)  # Déclencher une action Ansible


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
            'type_attack': attack_type
        }

        with open(self.filename, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
            writer.writerow(new_row)

        self.window_packets = []  # Efface la fenetre de paquets utilisé 
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
        dst_ip = packet[IP].dst
        self.current_ips.add(src_ip)  # Ajouter au lot courant
        self.current_ips.add(dst_ip)
        if TCP in packet:
            self.tcp_count += 1
        elif UDP in packet:
            self.udp_count += 1
        elif ICMP in packet:
            self.icmp_count += 1

        length = len(packet)

        self.window_packets.append((current_time, src_ip, dst_ip, length))
        if (current_time - self.last_write_time).total_seconds() >= self.window_size:
            self.write_window_statistics()
            self.last_write_time = current_time

    def start_capture(self):
        sniff(prn=self.process_packet, store=False)

    pass

def main():
    collector = NetworkDataCollector(window_size=5, filename='network_data_grouped_model.csv')
    thread = threading.Thread(target=collector.start_capture)
    thread.start()
    
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    try:
        client.connect("192.168.3.109", 1883)
    except Exception as e:
        print(f"Une erreur est survenue : {e}")
        
    thread2 = threading.Thread(target=manage_connection, args=(client,))
    thread2.start()
    client.loop_forever()

if __name__ == "__main__":
    main()

