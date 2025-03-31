import os
import time
import threading
import hashlib
from utils import find_processes_using_file, close_file_processes
from logger import log_event
from crypto_module import CryptoModule


class FileMonitor:
    def __init__(self, crypto_module, encrypted_file_path, decrypted_file_path, password, method, delete_after,
                 max_opens):
        self.crypto_module = crypto_module
        self.encrypted_file_path = encrypted_file_path
        self.decrypted_file_path = decrypted_file_path
        self.password = password
        self.method = method
        self.delete_after = delete_after
        self.max_opens = max_opens

        self.open_count = 0
        self.first_open_time = time.time()
        self.running = True

        self.original_hash = self._get_file_hash()
        self.original_hmac = self._get_file_hmac()
        self.original_drive = os.path.splitdrive(decrypted_file_path)[0]
        self.processes_using_file = set()

        self.monitor_thread = threading.Thread(target=self.monitor, daemon=True)
        self.monitor_thread.start()

    def _get_file_hash(self):
        try:
            if not os.path.exists(self.decrypted_file_path):
                return None
            with open(self.decrypted_file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None

    def _get_file_hmac(self):
        try:
            self.crypto_module.generate_key(self.password)
            with open(self.decrypted_file_path, 'rb') as f:
                data = f.read()
            return self.crypto_module._hmac_sign(data)
        except:
            return None

    def _secure_delete(self, path):
        try:
            if os.path.exists(path):
                length = os.path.getsize(path)
                with open(path, 'ba+', buffering=0) as f:
                    f.seek(0)
                    f.write(os.urandom(length))
                os.remove(path)
                log_event("Безопасное удаление", path, f"Размер: {length} байт")
        except Exception as e:
            log_event("Ошибка при безопасном удалении", path, str(e))

    def _destroy_files(self, reason):
        close_file_processes(self.decrypted_file_path)
        time.sleep(0.5)
        self._secure_delete(self.decrypted_file_path)
        self._secure_delete(self.encrypted_file_path)
        log_event("Удаление", self.decrypted_file_path, f"Причина: {reason}")
        self.running = False

    def force_destroy(self, reason="Принудительное удаление"):
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)
        self._destroy_files(reason)

    def monitor(self):
        try:
            missing_counter = 0

            while self.running:
                if not os.path.exists(self.decrypted_file_path):
                    missing_counter += 1
                    if missing_counter >= 3:
                        self._destroy_files("Файл удалён вручную")
                        break
                else:
                    missing_counter = 0

                current_processes = find_processes_using_file(self.decrypted_file_path)
                current_pids = {proc.pid for proc in current_processes}
                new_pids = current_pids - self.processes_using_file

                if new_pids:
                    self.open_count += len(new_pids)
                    self.processes_using_file.update(new_pids)
                    log_event("Открытие", self.decrypted_file_path, f"Новые PID: {new_pids}")

                    if self.open_count > self.max_opens:
                        self._destroy_files("Превышен лимит открытий")
                        break

                self.processes_using_file &= current_pids

                if self.delete_after:
                    elapsed_time = time.time() - self.first_open_time
                    if elapsed_time >= self.delete_after:
                        self._destroy_files("Таймер истек")
                        break

                current_hash = self._get_file_hash()
                if current_hash != self.original_hash:
                    self._destroy_files("Файл изменён")
                    break

                current_hmac = self._get_file_hmac()
                if current_hmac != self.original_hmac:
                    self._destroy_files("Подпись HMAC не совпадает")
                    break

                current_drive = os.path.splitdrive(self.decrypted_file_path)[0]
                if current_drive != self.original_drive:
                    self._destroy_files("Файл скопирован на другой диск")
                    break

                time.sleep(1)

        except Exception as e:
            log_event("Ошибка мониторинга", self.decrypted_file_path, str(e))
            self._destroy_files("Ошибка мониторинга")

    def stop(self):
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)


def start_monitoring(crypto_module, encrypted_file_path, decrypted_file_path, password, method, delete_after,
                     max_opens):
    return FileMonitor(crypto_module, encrypted_file_path, decrypted_file_path, password, method, delete_after,
                       max_opens)
