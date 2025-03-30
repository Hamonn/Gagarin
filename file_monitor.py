import os
import time
import threading
import hashlib
import pyperclip
from PyQt6.QtWidgets import QMessageBox
from utils import find_processes_using_file, close_file_processes


class FileMonitor:
    def __init__(self, crypto_module, encrypted_file_path, decrypted_file_path, password, method, delete_after,
                 copy_protection, max_opens):
        self.crypto_module = crypto_module
        self.encrypted_file_path = encrypted_file_path
        self.decrypted_file_path = decrypted_file_path
        self.password = password
        self.method = method
        self.delete_after = delete_after
        self.copy_protection = copy_protection
        self.max_opens = max_opens
        self.open_count = 0
        self.first_open_time = None
        self.original_hash = self._get_file_hash()
        self.running = True
        self.initial_clipboard = pyperclip.paste() if copy_protection else None
        self.processes_using_file = set()
        self.monitor_thread = threading.Thread(target=self.monitor, daemon=True)
        self.monitor_thread.start()

    def _get_file_hash(self):
        if not os.path.exists(self.decrypted_file_path):
            return None
        with open(self.decrypted_file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _destroy_files(self, reason):
        close_file_processes(self.decrypted_file_path)
        try:
            if os.path.exists(self.decrypted_file_path):
                os.remove(self.decrypted_file_path)
            if os.path.exists(self.encrypted_file_path):
                os.remove(self.encrypted_file_path)
            QMessageBox.warning(None, "Нарушение безопасности", f"Файлы удалены: {reason}")
        except Exception:
            QMessageBox.critical(None, "Ошибка", "Не удалось удалить файлы")
        self.running = False

    def monitor(self):
        try:
            clipboard_check_counter = 0
            while self.running and os.path.exists(self.decrypted_file_path):
                current_processes = find_processes_using_file(self.decrypted_file_path)
                current_pids = {proc.pid for proc in current_processes}
                new_pids = current_pids - self.processes_using_file
                if new_pids:
                    self.open_count += len(new_pids)
                    self.processes_using_file.update(new_pids)
                    if self.open_count >= self.max_opens:
                        self._destroy_files("Превышен лимит открытий")
                        break
                self.processes_using_file = self.processes_using_file & current_pids

                if self.first_open_time is None and current_pids:
                    self.first_open_time = time.time()

                if self.first_open_time:
                    elapsed_time = time.time() - self.first_open_time
                    if elapsed_time >= self.delete_after:
                        self._destroy_files("Таймер истек")
                        break

                if self.copy_protection:
                    clipboard_check_counter += 1
                    if clipboard_check_counter % 2 == 0:
                        current_clipboard = pyperclip.paste()
                        if current_clipboard != self.initial_clipboard:
                            self._destroy_files("Обнаружено копирование")
                            break

                current_hash = self._get_file_hash()
                if current_hash and current_hash != self.original_hash:
                    self._destroy_files("Обнаружены несанкционированные изменения")
                    break

                time.sleep(2)
        except Exception:
            self._destroy_files("Ошибка мониторинга")

    def stop(self):
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)


def start_monitoring(crypto_module, encrypted_file_path, decrypted_file_path, password, method, delete_after,
                     copy_protection, max_opens):
    monitor = FileMonitor(crypto_module, encrypted_file_path, decrypted_file_path, password, method, delete_after,
                          copy_protection, max_opens)
    return monitor