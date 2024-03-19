from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy import *
import pandas as pd
import datetime
import numpy as np
from collections import Counter

# Initialisation du DataFrame avec des colonnes supplémentaires pour de nouvelles caractéristiques
columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'length', 'icmp_type', 'tcp_flags', 'entropy_src_ip', 'entropy_dst_ip', 'window_tx']
df = pd.DataFrame(columns=columns)

# Fenêtre temporelle pour l'analyse (en secondes)
window_size = 300  # 5 minutes
window_packets = []

def calculate_entropy(ip_list):
    """Calcule l'entropie d'une liste d'adresses IP pour détecter la variabilité."""
    count = Counter(ip_list)
    probabilities = [n / len(ip_list) for n in count.values()]
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
    return entropy

def process_packet(packet):
    global df, window_packets
    current_time = datetime.datetime.now()

    # Extraction et traitement des données du paquet
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    length = len(packet)
    protocol = 'Other'
    src_port = dst_port = icmp_type = tcp_flags = None

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = 'TCP'
        tcp_flags = packet[TCP].flags
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = 'UDP'
    elif ICMP in packet:
        protocol = 'ICMP'
        icmp_type = packet[ICMP].type

    # Ajout des données du paquet à la fenêtre temporelle
    window_packets.append((current_time, src_ip, dst_ip, length))

    # Nettoyage des paquets hors de la fenêtre temporelle
    window_packets = [(t, src, dst, l) for (t, src, dst, l) in window_packets if (current_time - t).seconds < window_size]

    # Calcul de l'entropie et du volume total dans la fenêtre temporelle
    src_ips = [src for (_, src, _, _) in window_packets]
    dst_ips = [dst for (_, _, dst, _) in window_packets]
    total_tx = sum(l for (_, _, _, l) in window_packets)
    entropy_src = calculate_entropy(src_ips)
    entropy_dst = calculate_entropy(dst_ips)

    # Ajout des nouvelles caractéristiques au DataFrame
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
    df = df.append(new_row, ignore_index=True)

    def start_sniffing(self):
        # Démarrer la capture des paquets
        sniff(prn=self.packet_callback, store=False)

    start_sniffing(self=any)
# Rappel : Envisagez d'implémenter une routine pour sauvegarder périodiquement les données et réinitialiser le DataFrame pour la gestion de la mémoire.
