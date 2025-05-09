from scapy.all import sniff, TCP, IP
import socket
import sys
import time

BLACKLISTED_PORT = 443
PERSISTENCE_THRESHOLD = 2  

my_ip = socket.gethostbyname(socket.gethostname())

last_used_port = None
port_start_time = {}
persistent_ports = set()

def packet_callback(packet):
    global last_used_port

    if packet.haslayer(TCP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport

        if source_ip == my_ip:
            current_port = dest_port
        elif dest_ip == my_ip:
            current_port = source_port
        else:
            return

        if current_port == BLACKLISTED_PORT:
            return 

        if current_port != last_used_port:
            last_used_port = current_port
            sys.stdout.write(f"\rSon kullanılan port: {last_used_port}   ")
            sys.stdout.flush()

def start_sniffing():
    print("Ağ trafiği dinleniyor...")
    sniff(filter="tcp", prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
