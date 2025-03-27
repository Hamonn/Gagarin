import os
import hashlib
import time
import multiprocessing
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes


class CryptoModule:
    def __init__(self):
        self.key = None

    def generate_key(self, password: str):
        """Генерирует 256-битный ключ из пароля"""
        password_bytes = password.encode('utf-8')
        self.key = hashlib.sha256(password_bytes).digest()

    def encrypt_file(self, file_path: str, password: str, delete_after: int = None):
        """Шифрует файл AES-256 в режиме CBC"""
        if not os.path.exists(file_path):
            raise FileNotFoundError("Исходный файл не найден")

        self.generate_key(password)
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + ciphertext)

        # Удаление оригинального файла УБРАНО! Теперь он остаётся в системе.

        if delete_after:
            process = multiprocessing.Process(target=self._delete_file_after, args=(encrypted_file_path, delete_after))
            process.daemon = True  # Фоновый процесс
            process.start()

        return encrypted_file_path

    def decrypt_file(self, file_path: str, password: str):
        """Расшифровывает файл AES-256 в режиме CBC"""
        if not os.path.exists(file_path):
            raise FileNotFoundError("Зашифрованный файл не найден")

        self.generate_key(password)

        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 16:
            raise ValueError("Недостаточно данных для расшифровки")

        iv, ciphertext = data[:16], data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        try:
            padded_data = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_data, AES.block_size)
        except ValueError:
            raise ValueError("Ошибка расшифровки: Неверный пароль или повреждён файл")

        decrypted_file_path = file_path.replace(".enc", "_decrypted")
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        os.remove(file_path)  # Удаляем зашифрованный файл после расшифрования

        return decrypted_file_path

    @staticmethod
    def _delete_file_after(file_path, delay):
        """Удаляет файл через указанное время (работает в фоновом процессе)"""
        time.sleep(delay)
        if os.path.exists(file_path):
            os.remove(file_path)
