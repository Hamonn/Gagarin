import os
import hashlib
import json
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from utils import log_event

class CryptoModule:
    def __init__(self):
        self.backend = default_backend()

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, file_path, password, **options):
        if not os.path.exists(file_path):
            raise ValueError("Файл не найден")
        if len(password) < 8:
            raise ValueError("Пароль должен быть не короче 8 символов")

        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        iv = os.urandom(12) if options.get('method') == "AES-256-GCM" else os.urandom(16) if options.get('method') == "AES-256-CBC" else os.urandom(12)  # 12 bytes for ChaCha20
        meta = {
            "method": options.get("method", "AES-256-GCM"),
            "timer": options.get("timer_seconds", 0),
            "copy_protection": options.get("copy_protection", False),
            "bind": options.get("bind_to_ip_mac", False),
            "device_id": options.get("device_id"),
            "ip_address": options.get("ip_address"),
            "mac_address": options.get("mac_address"),
            "max_opens": options.get("max_opens", 5),
            "current_opens": 0,
            "restrict_modification": options.get("restrict_modification", False),
            "restrict_move": options.get("restrict_move", False)
        }

        with open(file_path, 'rb') as f:
            data = f.read()

        try:
            if meta['method'] == "AES-256-GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
                tag = encryptor.tag
            elif meta['method'] == "AES-256-CBC":
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data) + padder.finalize()
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                tag = b""
            else:  # ChaCha20
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=self.backend)
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
                tag = b""
        except Exception as e:
            log_event(f"Ошибка шифрования файла {file_path}: {str(e)}")
            raise

        meta_json = json.dumps(meta).encode()
        output = base64.b64encode(salt + iv + tag + meta_json + b'|' + encrypted_data)
        output_path = file_path + '.enc'
        with open(output_path, 'wb') as f:
            f.write(output)
        log_event(f"Файл зашифрован: {output_path}")
        return output_path

    def decrypt_file(self, file_path, password, output_path):
        if not os.path.exists(file_path):
            raise ValueError("Файл не найден")

        with open(file_path, 'rb') as f:
            data = base64.b64decode(f.read())

        salt = data[:16]
        iv = data[16:28] if data[28:30] == b'\x00\x10' else data[16:32]  # Adjust for GCM tag
        tag = data[28:44] if data[28:30] == b'\x00\x10' else b""
        separator_idx = data.find(b'|', 44 if tag else 32)
        meta_json = data[len(salt) + len(iv) + len(tag):separator_idx]
        encrypted_data = data[separator_idx + 1:]

        meta = json.loads(meta_json.decode())
        key = self.derive_key(password, salt)

        try:
            if meta['method'] == "AES-256-GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            elif meta['method'] == "AES-256-CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
            else:  # ChaCha20
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=self.backend)
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        except InvalidKey:
            log_event(f"Ошибка расшифровки файла {file_path}: неверный пароль")
            raise ValueError("Неверный пароль")
        except Exception as e:
            log_event(f"Ошибка расшифровки файла {file_path}: {str(e)}")
            raise

        if meta['current_opens'] >= meta['max_opens']:
            log_event(f"Ошибка расшифровки файла {file_path}: превышено количество открытий")
            raise ValueError("Превышено максимальное количество открытий")

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        meta['current_opens'] += 1
        new_meta_json = json.dumps(meta).encode()
        new_data = base64.b64encode(salt + iv + tag + new_meta_json + b'|' + encrypted_data)
        with open(file_path, 'wb') as f:
            f.write(new_data)

        log_event(f"Файл расшифрован: {output_path}")
        return output_path, meta