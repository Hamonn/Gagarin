import os
import json
import hashlib
from Crypto.Cipher import AES, Blowfish, DES3, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from uuid import getnode as get_mac


class CryptoModule:
    def __init__(self):
        self.key = None
        self.salt = b"MySuperSalt"

    def generate_key(self, password: str):
        self.key = PBKDF2(password, self.salt, dkLen=32, count=100000)

    def _get_mac_address(self):
        return ':'.join(['{:02x}'.format((get_mac() >> i) & 0xff)
                         for i in range(0, 2 * 6, 8)][::-1])

    def _hmac_sign(self, data: bytes) -> bytes:
        h = HMAC.new(self.key, digestmod=SHA256)
        h.update(data)
        return h.digest()

    def _hmac_verify(self, data: bytes, signature: bytes):
        h = HMAC.new(self.key, digestmod=SHA256)
        h.update(data)
        try:
            h.verify(signature)
        except ValueError:
            raise ValueError("Неверная подпись данных")

    def encrypt_file(self, file_path: str, password: str, method: str = "AES-256-CBC",
                     max_opens: int = 5, max_attempts: int = 3,
                     device_id: str = None, ip_address: str = None):
        if not os.path.exists(file_path):
            raise FileNotFoundError("Файл не найден")

        self.generate_key(password)

        with open(file_path, 'rb') as f:
            data = f.read()

        file_hash = hashlib.sha256(data).hexdigest()
        iv = get_random_bytes(16)
        nonce = get_random_bytes(12) if method == "ChaCha20" else b""

        if method == "ChaCha20":
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            encrypted = cipher.encrypt(data)
        elif method == "Blowfish":
            cipher = Blowfish.new(self.key[:16], Blowfish.MODE_CBC, iv[:8])
            encrypted = cipher.encrypt(pad(data, Blowfish.block_size))
        elif method == "DES3":
            cipher = DES3.new(self.key[:24], DES3.MODE_CBC, iv[:8])
            encrypted = cipher.encrypt(pad(data, DES3.block_size))
        else:  # AES-256-CBC
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(data, AES.block_size))

        metadata = {
            "original_name": os.path.basename(file_path),
            "file_hash": file_hash,
            "max_opens": max_opens,
            "current_opens": 0,
            "attempts_left": max_attempts,
            "method": method,
            "device_id": device_id,
            "ip_address": ip_address,
            "mac_address": self._get_mac_address()
        }

        meta_json = json.dumps(metadata).encode()
        hmac_sig = self._hmac_sign(encrypted)

        output_path = file_path + ".enc"
        with open(output_path, 'wb') as f:
            f.write(len(iv).to_bytes(1, 'big'))
            f.write(iv)
            f.write(len(nonce).to_bytes(1, 'big'))
            f.write(nonce)
            f.write(len(meta_json).to_bytes(4, 'big'))
            f.write(meta_json)
            f.write(len(hmac_sig).to_bytes(2, 'big'))
            f.write(hmac_sig)
            f.write(encrypted)

        return output_path

    def decrypt_file(self, file_path: str, password: str, method: str = "AES-256-CBC",
                     output_path: str = None, current_device_id: str = None, current_ip: str = None):
        if not os.path.exists(file_path):
            raise FileNotFoundError("Файл не найден")

        self.generate_key(password)
        with open(file_path, 'rb') as f:
            iv_len = int.from_bytes(f.read(1), 'big')
            iv = f.read(iv_len)
            nonce_len = int.from_bytes(f.read(1), 'big')
            nonce = f.read(nonce_len)
            meta_len = int.from_bytes(f.read(4), 'big')
            meta_bytes = f.read(meta_len)
            hmac_len = int.from_bytes(f.read(2), 'big')
            hmac_sig = f.read(hmac_len)
            encrypted_data = f.read()

        metadata = json.loads(meta_bytes.decode())

        if metadata.get("device_id") and current_device_id and metadata["device_id"] != current_device_id:
            raise PermissionError("Несанкционированное устройство")
        if metadata.get("ip_address") and current_ip and metadata["ip_address"] != current_ip:
            raise PermissionError("Несанкционированный IP")
        if metadata.get("mac_address") and metadata["mac_address"] != self._get_mac_address():
            raise PermissionError("MAC-адрес не совпадает")

        self._hmac_verify(encrypted_data, hmac_sig)

        # Обработка счётчика открытий
        metadata["current_opens"] += 1
        if metadata["current_opens"] > metadata["max_opens"]:
            os.remove(file_path)
            raise PermissionError("Превышен лимит открытий")

        if method == "ChaCha20":
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            decrypted = cipher.decrypt(encrypted_data)
        elif method == "Blowfish":
            cipher = Blowfish.new(self.key[:16], Blowfish.MODE_CBC, iv[:8])
            decrypted = unpad(cipher.decrypt(encrypted_data), Blowfish.block_size)
        elif method == "DES3":
            cipher = DES3.new(self.key[:24], DES3.MODE_CBC, iv[:8])
            decrypted = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
        else:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Проверка целостности
        file_hash = hashlib.sha256(decrypted).hexdigest()
        if file_hash != metadata["file_hash"]:
            metadata["attempts_left"] -= 1
            if metadata["attempts_left"] <= 0:
                os.remove(file_path)
                raise PermissionError("Превышен лимит попыток")
            raise ValueError("Хэш-сумма не совпадает")

        if not output_path:
            output_path = os.path.join(os.path.dirname(file_path), metadata["original_name"])

        with open(output_path, 'wb') as f:
            f.write(decrypted)

        # Обновить metadata (только current_opens и attempts_left)
        new_meta = json.dumps(metadata).encode()
        with open(file_path, 'rb') as f:
            content = f.read()

        prefix_len = 1 + iv_len + 1 + nonce_len
        content = (
            content[:prefix_len] +
            len(new_meta).to_bytes(4, 'big') + new_meta +
            content[prefix_len + meta_len + 2 + len(hmac_sig):]
        )

        with open(file_path, 'wb') as f:
            f.write(content)

        return output_path
