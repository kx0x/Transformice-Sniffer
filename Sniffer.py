import argparse
import json
from scapy.all import sniff, TCP, Raw
from struct import unpack
from datetime import datetime
import keyboard
import threading
import socket
import requests
from scapy.all import IP  # Üstte import edilmeli
import time
import pyperclip
import os
import logging
from queue import Queue
from utils.chat_utils import decode_chat_payload
from utils.file_utils import save_packets, append_message
from utils.packet_utils import decode_packet, process_packet

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='sniffer_debug.log'
)

my_ip = socket.gethostbyname(socket.gethostname())

parser = argparse.ArgumentParser(description="Transformice packet sniffer")
parser.add_argument(
    "-p", "--port",
    type=int,
    help="Dinlenecek Transformice TCP portu (belirtilmezse tüm TCP trafiği dinlenir)"
)

parser.add_argument(
    "--username",
    type=str,
    help="Takip edilecek kullanıcı adını giriniz."
)

parser.add_argument(
    "--only",
    type=str,
    choices=["chat", "all"],
    default="all",
    help="Yalnızca belirtilen türdeki paketleri göster (chat veya all)"
)

parser.add_argument(
    "-o", "--output",
    type=str,
    default="packets.json",
    help="Çıktı dosya adı (varsayılan: packets.json)"
)

args = parser.parse_args()
TRANSFORMICE_PORT = args.port
output_file = args.output

captured_packets = []
last_save_time = datetime.now()
last_used_port = TRANSFORMICE_PORT

if __name__ == "__main__":
    try:
        if args.port:
            print(r'''
                                 
                        )
                       (
                 /\  .-"""-.  /\
                //\\/  ,,,  \//\\
                |/\| ,;;;;;, |/\|
                //\\\;-"""-;///\\
               //  \/   .   \/  \\
              (| ,-_| \ | / |_-, |)
                //`__\.-.-./__`\\
               // /.-(() ())-.\ \\
              (\ |)   '---'   (| /)
               ` (|           |) `
                 \)           (/

               sniffer by klofrox
''')
            def packet_handler(p):
                global last_save_time, last_used_port
                result = process_packet(p, my_ip, args, captured_packets, output_file, last_save_time, last_used_port)
                if result is not None:
                    last_save_time, last_used_port = result

            sniff(filter=f"tcp port {args.port}", prn=packet_handler, store=0)
        else:
            print(r'''
                                 
                        )
                       (
                 /\  .-"""-.  /\
                //\\/  ,,,  \//\\
                |/\| ,;;;;;, |/\|
                //\\\;-"""-;///\\
               //  \/   .   \/  \\
              (| ,-_| \ | / |_-, |)
                //`__\.-.-./__`\\
               // /.-(() ())-.\ \\
              (\ |)   '---'   (| /)
               ` (|           |) `
                 \)           (/

               sniffer by klofrox
''')
            def packet_handler(p):
                global last_save_time, last_used_port
                result = process_packet(p, my_ip, args, captured_packets, output_file, last_save_time, last_used_port)
                if result is not None:
                    last_save_time, last_used_port = result

            sniff(filter="tcp", prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[!] Dinleme durduruldu. Paketler kaydediliyor...")
        save_packets(captured_packets, output_file)
