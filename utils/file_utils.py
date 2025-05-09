import json
import logging

def save_packets(captured_packets, output_file):
    """
    Save captured packets to a JSON file.
    
    Args:
        captured_packets (list): List of captured packets to save
        output_file (str): Path to the output file
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(captured_packets, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[✗] Paketler kaydedilemedi: {e}")
        logging.error(f"Paketler kaydedilemedi: {e}")

def append_message(message, filename):
    """
    Append a message to a text file.
    
    Args:
        message (str): Message to append
        filename (str): Path to the file
    """
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"{message}\n")
    except Exception as e:
        logging.error(f"Mesaj dosyaya yazılamadı: {e}") 