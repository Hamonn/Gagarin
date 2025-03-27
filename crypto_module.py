import os
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes


class CryptoModule:
    def __init__(self):
        self.key = None

    def generate_key(self, password: str):
        """Генерирует 256-битный ключ из пароля"""
        self.key = hashlib.sha256(password.encode('utf-8')).digest()

    def encrypt_file(self, file_path: str, password: str, delete_original=False):
        """Шифрует файл AES-256 (CBC)"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл '{file_path}' не найден")

        self.generate_key(password)
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            padded_data = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)

            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv + ciphertext)

            if delete_original:
                os.remove(file_path)

            return encrypted_file_path

        except Exception as e:
            raise RuntimeError(f"Ошибка шифрования: {e}")

    def decrypt_file(self, file_path: str, password: str, delete_encrypted=False):
        """Расшифровывает файл AES-256 (CBC)"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл '{file_path}' не найден")

        self.generate_key(password)

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if len(data) < 16:
                raise ValueError("Недостаточно данных для расшифровки")

            iv, ciphertext = data[:16], data[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)

            padded_data = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_data, AES.block_size)

            decrypted_file_path = file_path.replace(".enc", "_decrypted")
            with open(decrypted_file_path, 'wb') as f:
                f.write(plaintext)

            if delete_encrypted:
                os.remove(file_path)

            return decrypted_file_path

        except ValueError:
            raise ValueError("Ошибка расшифровки: Неверный пароль или повреждён файл")
        except Exception as e:
            raise RuntimeError(f"Ошибка расшифровки: {e}")
