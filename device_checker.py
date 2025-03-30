import uuid
import socket
import platform


def get_device_id():
    try:
        device_id = str(uuid.getnode()) + platform.node()
        return device_id
    except Exception:
        return "unknown_device"


def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception:
        return "unknown_ip"