from scapy.all import sniff, IP, ICMP
import logging

# Configuration du logging pour écrire dans un fichier de log
logging.basicConfig(filename='/var/log/fireconnect/icmp_traffic.log', level=logging.WARNING,
                    format='%(asctime)s - %(message)s')

# Liste des adresses IP des hôtes que vous voulez surveiller
HOSTS_IP = ["172.20.10.2"]  # Exemple d'adresses IP

# Dictionnaire pour le nombre de pings reçus par chaque hôte
ping_counts = {host: 0 for host in HOSTS_IP}

def detect_icmp(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        ip_src = packet[IP].src  # L'adresse IP source du paquet
        ip_dst = packet[IP].dst  # L'adresse IP de destination du paquet
        # Vérifie si l'adresse IP de destination est dans notre liste d'hôtes
        if ip_dst in HOSTS_IP:
            # Incrémente le compteur pour cet hôte spécifique
            ping_counts[ip_dst] += 1

            # Vérifie si le nombre de pings pour cet hôte est un multiple de 5
            if ping_counts[ip_dst] % 5 == 0:
                alert_message = f"Alerte : {ip_dst} a reçu {ping_counts[ip_dst]} pings de {ip_src}!"
                print(alert_message)
                logging.warning(alert_message)

# Construire le filtre pour écouter tous les hôtes spécifiés
hosts_filter = " or ".join([f"ip dst {host}" for host in HOSTS_IP])
filter_rule = f"icmp and ({hosts_filter})"

# Utilisez un filtre pour capturer uniquement les paquets ICMP destinés aux adresses IP spécifiées
sniff(filter=filter_rule, prn=detect_icmp, store=False)
