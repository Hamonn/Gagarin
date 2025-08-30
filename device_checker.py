import uuid
import socket
from utils import log_event

def get_device_id():
    try:
        device_id = str(uuid.getnode())
        log_event(f"Получен ID устройства: {device_id}")
        return device_id
    except Exception as e:
        log_event(f"Ошибка получения ID устройства: {str(e)}")
        return "unknown"

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        log_event(f"Получен IP-адрес: {ip}")
        return ip
    except Exception as e:
        log_event(f"Ошибка получения IP-адреса: {str(e)}")
        return "127.0.0.1"