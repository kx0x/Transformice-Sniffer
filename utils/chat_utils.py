import os
import time
import pyperclip
import logging

def decode_chat_payload(payload_bytes):
    try:
        offset = 1
        nick_len = payload_bytes[offset]
        offset += 1
        nick = bytes(payload_bytes[offset:offset + nick_len]).decode("utf-8", errors="ignore")
        offset += nick_len

        if offset >= len(payload_bytes):
            return f"{nick}: [Mesaj yok]"

        if payload_bytes[offset] == 0:
            offset += 1

        msg_len = payload_bytes[offset]
        offset += 1
        msg = bytes(payload_bytes[offset:offset + msg_len]).decode("utf-8", errors="ignore")

        return f"{nick}: {msg}"
    except Exception as e:
        return f"[HATA]: {e}" 