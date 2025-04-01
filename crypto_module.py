import os
import json
import base64
import uuid
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes

backend = default_backend()

class CryptoModule:
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=backend
        )
        return kdf.derive(password.encode())

    def _pad(self, data: bytes) -> bytes:
        padder = sym_padding.PKCS7(128).padder()
        return padder.update(data) + padder.finalize()

    def _unpad(self, data: bytes) -> bytes:
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    def _pw_hash(self, password, max_opens):
        combo = f"{password}:{max_opens}".encode()
        return hashlib.sha256(combo).hexdigest()

    def _get_mac(self):
        mac = uuid.getnode()
        return ':'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -8, -8)])

    def encrypt_file(self, input_path, password, **options):
        with open(input_path, "rb") as f:
            file_data = f.read()

        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(password, salt)

        metadata = {
            "method": options.get("method", "AES-256-CBC"),
            "timer": options.get("timer_seconds", 0),
            "copy_protection": options.get("copy_protection", False),
            "bind": options.get("bind_to_ip_mac", False),
            "device_id": options.get("device_id"),
            "ip_address": options.get("ip_address"),
            "mac_address": self._get_mac() if options.get("bind_to_ip_mac") else None,
            "max_opens": options.get("max_opens", 5),
            "current_opens": 0,
            "restrict_modification": options.get("restrict_modification", False),
            "restrict_move": options.get("restrict_move", False),
            "pw_hash": self._pw_hash(password, options.get("max_opens", 5))
        }

        meta_padded = self._pad(json.dumps(metadata).encode())
        file_padded = self._pad(file_data)
        payload = file_padded + meta_padded

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encrypted = cipher.encryptor().update(payload) + cipher.encryptor().finalize()

        meta_len_bytes = len(meta_padded).to_bytes(4, 'big')

        out_path = input_path + ".enc"
        with open(out_path, "wb") as f:
            f.write(salt + iv + encrypted + meta_len_bytes)

        return out_path

    def decrypt_file(self, input_path, password, output_path):
        with open(input_path, "rb") as f:
            raw = f.read()

        meta_len = int.from_bytes(raw[-4:], 'big')
        raw_data = raw[:-4]

        salt = raw_data[:16]
        iv = raw_data[16:32]
        encrypted = raw_data[32:]

        key = self._derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decrypted = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()

        meta_padded = decrypted[-meta_len:]
        file_padded = decrypted[:-meta_len]

        try:
            meta = json.loads(self._unpad(meta_padded).decode())
            file_data = self._unpad(file_padded)
        except Exception as e:
            raise ValueError("Ошибка расшифровки или повреждённые данные") from e

        if self._pw_hash(password, meta["max_opens"]) != meta.get("pw_hash"):
            raise ValueError("Пароль не соответствует параметрам доступа")

        if meta.get("max_opens") and meta["current_opens"] >= meta["max_opens"]:
            os.remove(input_path)
            raise PermissionError("Превышен лимит расшифровок. Файл удалён.")

        with open(output_path, "wb") as f:
            f.write(file_data)

        meta["current_opens"] += 1
        self._write_updated(input_path, file_data, meta, password)

        return output_path, meta

    def _write_updated(self, path, file_data, metadata, password):
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(password, salt)

        meta_padded = self._pad(json.dumps(metadata).encode())
        file_padded = self._pad(file_data)
        payload = file_padded + meta_padded

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encrypted = cipher.encryptor().update(payload) + cipher.encryptor().finalize()

        meta_len_bytes = len(meta_padded).to_bytes(4, 'big')

        with open(path, "wb") as f:
            f.write(salt + iv + encrypted + meta_len_bytes)

    def update_meta_field(self, enc_path, password, current_opens):
        temp_output = "_temp_for_update"
        try:
            self.decrypt_file(enc_path, password, temp_output)
            if os.path.exists(temp_output):
                os.remove(temp_output)
        except Exception:
            pass
