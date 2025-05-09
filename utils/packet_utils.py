import re
import logging
import time
from struct import unpack
from datetime import datetime
from scapy.all import IP, TCP, Raw
from utils.chat_utils import decode_chat_payload
from utils.file_utils import save_packets, append_message

COMMAND_NAMES = {
    (29, 1542): "chat_message",
    (1, 2049): "Login Authentication",
    (30, 1542): "Chat Message",
    (71, 21573): "Image Request",
    (72, 21588): "Image Response",
    (19, 828): "Player Info"
}

online_users = set()

def decode_packet(payload, direction, my_ip, args=None):
    """
    Decode a packet and process any commands found in the payload.
    
    Args:
        payload (bytes): The packet payload
        direction (str): Direction of the packet ("→ Client" or "← Server")
        my_ip (str): The local IP address
        args (argparse.Namespace, optional): Command line arguments
    
    Returns:
        dict: Decoded packet information
    """
    if len(payload) < 3:
        return None

    channel = payload[0]
    cmd = unpack('<H', payload[1:3])[0]
    rest = payload[3:]
    cmd_name = COMMAND_NAMES.get((channel, cmd), "Unknown")
    if cmd == 1542:
        cmd_name = "Chat Message"

    result = {
        'Timestamp': datetime.now().isoformat(),
        'Direction': direction,
        'Channel ID': channel,
        'Command ID': cmd,
        'Command Name': cmd_name,
        'Payload (Hex)': rest.hex(),
        'Payload (Bytes)': list(rest)
    }

    try:
        # Decode channel 19, command 828
        if (channel, cmd) == (19, 828):
            try:
                offset = 0
                while offset < len(rest):
                    name_len = rest[offset]
                    offset += 1
                    name = rest[offset:offset + name_len].decode("utf-8", errors="ignore")
                    offset += name_len
                    result['Player Name'] = name
            except Exception as e:
                logging.error(f"Error decoding player info: {e}")

        offset = 1
        nick_len = rest[offset]
        offset += 1
        nick = rest[offset:offset + nick_len].decode("utf-8", errors="ignore")

            # Çevrim içi / dışı takibi (Command ID 257, channel 26 gibi)
        if (channel, cmd) == (26, 257):
            try:
                offset = 3
                while offset < len(rest):
                    name_len = rest[offset]
                    offset += 1
                    name = rest[offset:offset + name_len].decode("utf-8", errors="ignore")
                    offset += name_len

                    if name not in online_users:
                        online_users.add(name)
                        print(f"\033[92m[Sniffer]: {name} çevrim içi oldu.\033[0m")
            except Exception:
                pass


        if cmd in {1542}:
            if re.match(r"^[A-Za-z0-9]+#[0-9]{4}$", nick):
                result['Command Name'] = "Chat Message"
                decoded_msg = decode_chat_payload(rest)
                result['Message'] = decoded_msg
    except Exception:
        pass

    return result

def process_packet(packet, my_ip, args, captured_packets, output_file, last_save_time, last_used_port):
    """
    Process a captured packet.
    
    Args:
        packet: The captured packet
        my_ip (str): The local IP address
        args (argparse.Namespace): Command line arguments
        captured_packets (list): List to store captured packets
        output_file (str): Path to save captured packets
        last_save_time (datetime): Last time packets were saved
        last_used_port (int): Last used port
    
    Returns:
        tuple: Updated last_save_time and last_used_port
    """
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp_layer = packet.getlayer(TCP)

        if tcp_layer.dport != last_used_port and tcp_layer.sport != last_used_port:
            last_used_port = tcp_layer.dport if tcp_layer.dport != 0 else tcp_layer.sport

        if tcp_layer.dport == last_used_port or tcp_layer.sport == last_used_port:
            ip_layer = packet.getlayer(IP)
            direction = "→ Client" if ip_layer.src == my_ip else "← Server"
            raw_data = bytes(packet[Raw].load)
            
            if len(raw_data) >= 3 and raw_data[0] == 23 and unpack('<H', raw_data[1:3])[0] == 771:
                return last_save_time, last_used_port
                
            decoded = decode_packet(raw_data, direction, my_ip, args)

            if not decoded:
                return last_save_time, last_used_port

            if args.only == "chat":
                if decoded.get("Command Name") == "Chat Message":
                    message = decoded.get("Message")
                    if message:
                        print(f"\033[93m[Sniffer]:\033[0m \033[97m{message}\033[0m")
                return None  #

            captured_packets.append(decoded)

            color = "\033[92m" if direction == "→ Client" else "\033[94m"
            reset = "\033[0m"
            print(f"{color}\n--- Transformice Packet ---")
            for k, v in decoded.items():
                print(f"{k}: {v}")
            print(reset, end='')

            if direction == "→ Client":
                append_message(decoded.get('Message', '[Mesaj Yok]'), "messages.txt")
            else:
                append_message(decoded.get('Message', '[Mesaj Yok]'), "sent_messages.txt")

            now = datetime.now()
            if (now - last_save_time).total_seconds() >= 1:
                save_packets(captured_packets, output_file)
                last_save_time = now

    return last_save_time, last_used_port 