import os
import hashlib
import json
from Cryptodome.Cipher import AES, ChaCha20, Blowfish
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes


class CryptoModule:
    def __init__(self):
        self.key = None

    def generate_key(self, password: str, method: str):
        password_bytes = password.encode('utf-8')
        if method == "AES-256-CBC":
            self.key = hashlib.sha256(password_bytes).digest()
        elif method == "ChaCha20":
            self.key = hashlib.sha256(password_bytes).digest()
        elif method == "Blowfish":
            self.key = hashlib.sha1(password_bytes).digest()[:16]
        else:
            raise ValueError(f"Неподдерживаемый метод шифрования: {method}")

    def encrypt_file(self, file_path: str, password: str, method: str = "AES-256-CBC", max_opens: int = None,
                     max_attempts: int = 3, device_id: str = None, ip_address: str = None):
        if not os.path.exists(file_path):
            raise FileNotFoundError("Исходный файл не найден")

        self.generate_key(password, method)
        encrypted_file_path = file_path + ".enc"

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        metadata = {
            "max_opens": max_opens if max_opens is not None else float('inf'),
            "current_opens": 0,
            "max_attempts": max_attempts,
            "attempts_left": max_attempts,
            "file_hash": hashlib.sha256(plaintext).hexdigest(),
            "device_id": device_id,
            "ip_address": ip_address
        }
        metadata_bytes = json.dumps(metadata).encode('utf-8')

        encrypted_data = None

        if method == "AES-256-CBC":
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            metadata_cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_metadata = pad(metadata_bytes, AES.block_size)
            metadata_ciphertext = metadata_cipher.encrypt(padded_metadata)
            encrypted_data = iv + len(metadata_ciphertext).to_bytes(4, 'big') + metadata_ciphertext + ciphertext

        elif method == "ChaCha20":
            nonce = get_random_bytes(8)
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            ciphertext = cipher.encrypt(plaintext)
            metadata_cipher = ChaCha20.new(key=self.key, nonce=nonce)
            metadata_ciphertext = metadata_cipher.encrypt(metadata_bytes)
            encrypted_data = nonce + len(metadata_ciphertext).to_bytes(4, 'big') + metadata_ciphertext + ciphertext

        elif method == "Blowfish":
            iv = get_random_bytes(8)
            cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            padded_data = pad(plaintext, Blowfish.block_size)
            ciphertext = cipher.encrypt(padded_data)
            metadata_cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            padded_metadata = pad(metadata_bytes, Blowfish.block_size)
            metadata_ciphertext = metadata_cipher.encrypt(padded_metadata)
            encrypted_data = iv + len(metadata_ciphertext).to_bytes(4, 'big') + metadata_ciphertext + ciphertext

        else:
            raise ValueError(f"Неподдерживаемый метод шифрования: {method}")

        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        return encrypted_file_path

    def decrypt_file(self, file_path: str, password: str, method: str = "AES-256-CBC", output_path: str = None,
                     current_device_id: str = None, current_ip: str = None):
        if not os.path.exists(file_path):
            raise FileNotFoundError("Зашифрованный файл не найден")

        self.generate_key(password, method)
        decrypted_file_path = output_path if output_path else file_path.replace(".enc", "_decrypted")

        with open(file_path, 'rb') as f:
            data = f.read()

        if method == "AES-256-CBC":
            iv = data[:16]
            metadata_len = int.from_bytes(data[16:20], 'big')
            metadata_ciphertext = data[20:20 + metadata_len]
            ciphertext = data[20 + metadata_len:]
            metadata_cipher = AES.new(self.key, AES.MODE_CBC, iv)
            try:
                metadata_padded = metadata_cipher.decrypt(metadata_ciphertext)
                metadata_bytes = unpad(metadata_padded, AES.block_size)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except ValueError:
                raise ValueError("Неверный пароль или поврежденные метаданные")
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            try:
                plaintext_padded = cipher.decrypt(ciphertext)
                plaintext = unpad(plaintext_padded, AES.block_size)
            except ValueError:
                metadata["attempts_left"] -= 1
                if metadata["attempts_left"] <= 0:
                    os.remove(file_path)
                    raise PermissionError("Превышено количество неверных попыток!")
                self._update_metadata(file_path, metadata, method, iv, ciphertext)
                raise ValueError("Неверный пароль или поврежденные данные")

        elif method == "ChaCha20":
            nonce = data[:8]
            metadata_len = int.from_bytes(data[8:12], 'big')
            metadata_ciphertext = data[12:12 + metadata_len]
            ciphertext = data[12 + metadata_len:]
            metadata_cipher = ChaCha20.new(key=self.key, nonce=nonce)
            try:
                metadata_bytes = metadata_cipher.decrypt(metadata_ciphertext)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except ValueError:
                raise ValueError("Неверный пароль или поврежденные метаданные")
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

        elif method == "Blowfish":
            iv = data[:8]
            metadata_len = int.from_bytes(data[8:12], 'big')
            metadata_ciphertext = data[12:12 + metadata_len]
            ciphertext = data[12 + metadata_len:]
            metadata_cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            try:
                metadata_padded = metadata_cipher.decrypt(metadata_ciphertext)
                metadata_bytes = unpad(metadata_padded, Blowfish.block_size)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except ValueError:
                raise ValueError("Неверный пароль или поврежденные метаданные")
            cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            try:
                plaintext_padded = cipher.decrypt(ciphertext)
                plaintext = unpad(plaintext_padded, Blowfish.block_size)
            except ValueError:
                raise ValueError("Неверный пароль или поврежденные данные")

        else:
            raise ValueError(f"Неподдерживаемый метод шифрования: {method}")

        if current_device_id and metadata["device_id"] and metadata["device_id"] != current_device_id and self.device_restriction:
            os.remove(file_path)
            raise PermissionError("Несанкционированное устройство!")
        if current_ip and metadata["ip_address"] and metadata["ip_address"] != current_ip and self.device_restriction:
            os.remove(file_path)
            raise PermissionError("Несанкционированный IP!")

        if metadata["attempts_left"] <= 0:
            os.remove(file_path)
            raise PermissionError("Превышено количество неверных попыток ввода пароля!")

        calculated_hash = hashlib.sha256(plaintext).hexdigest()
        if calculated_hash != metadata["file_hash"]:
            metadata["attempts_left"] -= 1
            if metadata["attempts_left"] <= 0:
                os.remove(file_path)
                raise PermissionError("Превышено количество неверных попыток!")
            self._update_metadata(file_path, metadata, method, iv if method != "ChaCha20" else nonce, ciphertext)
            raise ValueError("Хэш данных не совпадает")

        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)
        return decrypted_file_path

    def _update_metadata(self, file_path: str, metadata: dict, method: str, iv: bytes, ciphertext: bytes):
        metadata_bytes = json.dumps(metadata).encode('utf-8')
        if method == "AES-256-CBC":
            padded_metadata = pad(metadata_bytes, AES.block_size)
            metadata_cipher = AES.new(self.key, AES.MODE_CBC, iv)
            metadata_ciphertext = metadata_cipher.encrypt(padded_metadata)
            updated_data = iv + len(metadata_ciphertext).to_bytes(4, 'big') + metadata_ciphertext + ciphertext
        elif method == "ChaCha20":
            nonce = iv
            metadata_cipher = ChaCha20.new(key=self.key, nonce=nonce)
            metadata_ciphertext = metadata_cipher.encrypt(metadata_bytes)
            updated_data = nonce + len(metadata_ciphertext).to_bytes(4, 'big') + metadata_ciphertext + ciphertext
        elif method == "Blowfish":
            padded_metadata = pad(metadata_bytes, Blowfish.block_size)
            metadata_cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            metadata_ciphertext = metadata_cipher.encrypt(padded_metadata)
            updated_data = iv + len(metadata_ciphertext).to_bytes(4, 'big') + metadata_ciphertext + ciphertext
        else:
            raise ValueError(f"Неподдерживаемый метод шифрования: {method}")

        with open(file_path, 'wb') as f:
            f.write(updated_data)