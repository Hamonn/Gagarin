import time
import threading
import psutil
from utils import calculate_file_hash, get_file_drive, kill_processes_with_cmdline_reference_to_file, log_event

class FileGuard(threading.Thread):
    def __init__(self, file_path, allowed_drive, original_hash, callback):
        super().__init__()
        self.file_path = file_path
        self.allowed_drive = allowed_drive
        self.original_hash = original_hash
        self.callback = callback
        self.running = True

    def run(self):
        while self.running:
            try:
                if not os.path.exists(self.file_path):
                    self.callback("Файл удалён или перемещён")
                    log_event(f"FileGuard: Файл {self.file_path} удалён или перемещён")
                    return
                if self.allowed_drive and get_file_drive(self.file_path) != self.allowed_drive:
                    self.callback("Файл перемещён на другой диск")
                    log_event(f"FileGuard: Файл {self.file_path} перемещён на другой диск")
                    return
                if self.original_hash and calculate_file_hash(self.file_path) != self.original_hash:
                    self.callback("Файл изменён")
                    log_event(f"FileGuard: Файл {self.file_path} изменён")
                    return
            except Exception as e:
                log_event(f"FileGuard: Ошибка проверки файла {self.file_path}: {str(e)}")
            time.sleep(1)

    def stop(self):
        self.running = False
        log_event(f"FileGuard остановлен для {self.file_path}")

class USBFileGuard(threading.Thread):
    def __init__(self, file_path, callback):
        super().__init__()
        self.file_path = file_path
        self.callback = callback
        self.running = True

    def run(self):
        while self.running:
            for disk in psutil.disk_partitions():
                try:
                    if 'removable' in disk.opts.lower():
                        for root, _, files in os.walk(disk.mountpoint):
                            for file in files:
                                if file == os.path.basename(self.file_path):
                                    self.callback("Файл обнаружен на USB-устройстве")
                                    log_event(f"USBFileGuard: Файл {self.file_path} обнаружен на USB")
                                    return
                except Exception as e:
                    log_event(f"USBFileGuard: Ошибка проверки USB для {self.file_path}: {str(e)}")
            time.sleep(1)

    def stop(self):
        self.running = False
        log_event(f"USBFileGuard остановлен для {self.file_path}")