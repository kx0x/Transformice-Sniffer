import re
from datetime import datetime, timedelta
from collections import defaultdict

player_status = {}
last_seen_time = defaultdict(lambda: datetime.min)

def extract_text_fields(payload_bytes):
    texts = []
    i = 0
    while i < len(payload_bytes):
        length = payload_bytes[i]
        if i + 1 + length <= len(payload_bytes):
            try:
                text = payload_bytes[i+1:i+1+length].decode("utf-8")
                texts.append(text)
            except:
                pass
        i += length + 1
    return texts

def analyze_command_257(payload_hex, timestamp):
    payload_bytes = bytes.fromhex(payload_hex)
    texts = extract_text_fields(payload_bytes)
    if len(texts) >= 2 and "#" in texts[1]:
        player = texts[1]
        now = datetime.fromisoformat(timestamp)

        if player not in player_status:
            print(f"[{timestamp}] {player} çevrim **içi** oldu.")
            player_status[player] = "online"
        else:
            last_seen = last_seen_time[player]
            if now - last_seen > timedelta(seconds=1):
                print(f"[{timestamp}] {player} çevrim **dışı** oldu.")
                player_status[player] = "offline"

        last_seen_time[player] = now

def parse_log_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        lines = f.read().split("--- Transformice Packet ---")
    
    for block in lines:
        if not block.strip():
            continue
        timestamp_match = re.search(r"Timestamp: (.+)", block)
        command_id_match = re.search(r"Command ID: (\d+)", block)
        payload_match = re.search(r"Payload \(Hex\): ([0-9a-fA-F]+)", block)

        if timestamp_match and command_id_match and payload_match:
            timestamp = timestamp_match.group(1).strip()
            command_id = int(command_id_match.group(1))
            payload_hex = payload_match.group(1).strip()

            if command_id == 257:
                analyze_command_257(payload_hex, timestamp)

if __name__ == "__main__":
    parse_log_file("log.txt")
