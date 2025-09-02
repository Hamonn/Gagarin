import os
import time
import threading
import psutil
import platform
import hashlib
from pathlib import Path
from typing import Optional, Callable

# Импорт функций utils с обработкой ошибок
try:
    from utils import calculate_file_hash, get_file_drive, kill_processes_with_cmdline_reference_to_file, log_event
except ImportError:
    # Если utils недоступен, создаем базовые функции
    def calculate_file_hash(file_path: str) -> str:
        """Вычисляет SHA-256 хеш файла"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            print(f"Ошибка при вычислении хеша: {e}")
            return ""
    
    def get_file_drive(file_path: str) -> str:
        """Получает диск, на котором находится файл"""
        try:
            if platform.system() == "Windows":
                return os.path.splitdrive(os.path.abspath(file_path))[0]
            else:
                # Для Unix-систем возвращаем точку монтирования
                path = Path(file_path).resolve()
                for part in psutil.disk_partitions():
                    if str(path).startswith(part.mountpoint):
                        return part.mountpoint
                return "/"
        except Exception as e:
            print(f"Ошибка при получении диска: {e}")
            return ""
    
    def kill_processes_with_cmdline_reference_to_file(file_path: str):
        """Завершает процессы, связанные с файлом"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['cmdline'] and any(file_path in cmd for cmd in proc.info['cmdline']):
                        proc.terminate()
                        print(f"Завершен процесс {proc.info['name']} (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Ошибка при завершении процессов: {e}")
    
    def log_event(message: str):
        """Логирование событий"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")


class FileGuard(threading.Thread):
    """Класс для мониторинга файла на предмет изменений, перемещения или удаления"""
    
    def __init__(self, file_path: str, allowed_drive: Optional[str] = None, 
                 original_hash: Optional[str] = None, callback: Optional[Callable] = None):
        super().__init__()
        self.file_path = os.path.abspath(file_path)
        self.allowed_drive = allowed_drive
        self.original_hash = original_hash
        self.callback = callback or self._default_callback
        self.running = True
        self.daemon = True  # Поток будет завершен при завершении основного процесса
        
        # Проверяем существование файла при инициализации
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Файл не найден: {self.file_path}")
        
        # Вычисляем оригинальный хеш если не предоставлен
        if not self.original_hash:
            self.original_hash = calculate_file_hash(self.file_path)
        
        # Определяем разрешенный диск если не предоставлен
        if not self.allowed_drive:
            self.allowed_drive = get_file_drive(self.file_path)
        
        log_event(f"FileGuard инициализирован для {self.file_path}")
    
    def _default_callback(self, message: str):
        """Callback по умолчанию"""
        log_event(f"НАРУШЕНИЕ ЗАЩИТЫ: {message}")
        # Завершаем связанные процессы
        kill_processes_with_cmdline_reference_to_file(self.file_path)
    
    def run(self):
        """Основной цикл мониторинга"""
        log_event(f"FileGuard запущен для {self.file_path}")
        
        while self.running:
            try:
                # Проверка существования файла
                if not os.path.exists(self.file_path):
                    self.callback("Файл удалён или перемещён")
                    log_event(f"FileGuard: Файл {self.file_path} удалён или перемещён")
                    self.running = False
                    continue
                
                # Проверка диска
                if self.allowed_drive:
                    current_drive = get_file_drive(self.file_path)
                    if current_drive != self.allowed_drive:
                        self.callback(f"Файл перемещён с {self.allowed_drive} на {current_drive}")
                        log_event(f"FileGuard: Файл {self.file_path} перемещён на другой диск")
                        self.running = False
                        continue
                
                # Проверка целостности
                if self.original_hash:
                    try:
                        current_hash = calculate_file_hash(self.file_path)
                        if current_hash and current_hash != self.original_hash:
                            self.callback("Файл изменён (нарушена целостность)")
                            log_event(f"FileGuard: Файл {self.file_path} изменён")
                            self.running = False
                            continue
                    except PermissionError:
                        log_event(f"FileGuard: Нет доступа к файлу {self.file_path}")
                    except Exception as e:
                        log_event(f"FileGuard: Ошибка проверки хеша: {str(e)}")
                
            except Exception as e:
                log_event(f"FileGuard: Критическая ошибка при проверке {self.file_path}: {str(e)}")
            
            time.sleep(0.5)  # Уменьшили интервал для более быстрого обнаружения
        
        log_event(f"FileGuard завершил работу для {self.file_path}")
    
    def stop(self):
        """Остановка мониторинга"""
        self.running = False
        log_event(f"FileGuard получил сигнал остановки для {self.file_path}")


class USBFileGuard(threading.Thread):
    """Класс для мониторинга появления файла на USB-устройствах"""
    
    def __init__(self, file_path: str, callback: Optional[Callable] = None):
        super().__init__()
        self.file_path = os.path.abspath(file_path)
        self.filename = os.path.basename(self.file_path)
        self.callback = callback or self._default_callback
        self.running = True
        self.daemon = True
        self.checked_usb_devices = set()
        
        log_event(f"USBFileGuard инициализирован для поиска {self.filename}")
    
    def _default_callback(self, message: str):
        """Callback по умолчанию"""
        log_event(f"USB НАРУШЕНИЕ: {message}")
    
    def _is_removable_drive(self, partition) -> bool:
        """Проверяет, является ли диск съемным"""
        try:
            if platform.system() == "Windows":
                return 'removable' in partition.opts.lower()
            else:
                # Для Linux/macOS проверяем типичные точки монтирования
                mount_point = partition.mountpoint.lower()
                return any(usb_path in mount_point for usb_path in ['/media', '/mnt', '/run/media'])
        except Exception:
            return False
    
    def _scan_usb_device(self, mountpoint: str) -> bool:
        """Сканирует USB устройство на предмет наличия файла"""
        try:
            # Ограничиваем глубину поиска для производительности
            max_depth = 3
            
            for root, dirs, files in os.walk(mountpoint):
                # Ограничиваем глубину поиска
                depth = root.replace(mountpoint, '').count(os.sep)
                if depth >= max_depth:
                    dirs[:] = []  # Не идем глубже
                
                # Проверяем файлы в текущей директории
                for file in files:
                    if file == self.filename:
                        file_path = os.path.join(root, file)
                        # Дополнительная проверка по размеру или хешу
                        try:
                            if os.path.getsize(file_path) > 0:
                                return True
                        except Exception:
                            continue
                    
                    # Прерываем поиск если получили сигнал остановки
                    if not self.running:
                        return False
                        
        except (PermissionError, OSError):
            # Игнорируем недоступные директории
            pass
        except Exception as e:
            log_event(f"USBFileGuard: Ошибка сканирования {mountpoint}: {str(e)}")
        
        return False
    
    def run(self):
        """Основной цикл мониторинга USB"""
        log_event(f"USBFileGuard запущен для поиска {self.filename}")
        
        while self.running:
            try:
                current_usb_devices = set()
                
                for partition in psutil.disk_partitions():
                    if not self.running:
                        break
                    
                    try:
                        if self._is_removable_drive(partition):
                            mountpoint = partition.mountpoint
                            current_usb_devices.add(mountpoint)
                            
                            # Проверяем только новые устройства
                            if mountpoint not in self.checked_usb_devices:
                                log_event(f"USBFileGuard: Обнаружено новое USB устройство {mountpoint}")
                                
                                if self._scan_usb_device(mountpoint):
                                    self.callback(f"Файл '{self.filename}' обнаружен на USB-устройстве {mountpoint}")
                                    log_event(f"USBFileGuard: Файл {self.filename} найден на USB {mountpoint}")
                                    # Можно добавить действие - удаление файла с USB
                                
                                self.checked_usb_devices.add(mountpoint)
                    
                    except Exception as e:
                        log_event(f"USBFileGuard: Ошибка проверки раздела {partition.device}: {str(e)}")
                
                # Очищаем список от отключенных устройств
                self.checked_usb_devices &= current_usb_devices
                
            except Exception as e:
                log_event(f"USBFileGuard: Критическая ошибка: {str(e)}")
            
            time.sleep(2)  # Интервал проверки USB устройств
        
        log_event(f"USBFileGuard завершил работу для {self.filename}")
    
    def stop(self):
        """Остановка мониторинга"""
        self.running = False
        log_event(f"USBFileGuard получил сигнал остановки для {self.filename}")


# Дополнительный класс для комплексной защиты
class ComprehensiveFileProtection:
    """Комплексная защита файла"""
    
    def __init__(self, file_path: str, enable_usb_monitoring: bool = True):
        self.file_path = file_path
        self.file_guard = None
        self.usb_guard = None
        self.enable_usb_monitoring = enable_usb_monitoring
        
    def start_protection(self, callback: Optional[Callable] = None):
        """Запуск защиты"""
        try:
            # Запускаем основную защиту файла
            self.file_guard = FileGuard(self.file_path, callback=callback)
            self.file_guard.start()
            
            # Запускаем мониторинг USB если включен
            if self.enable_usb_monitoring:
                self.usb_guard = USBFileGuard(self.file_path, callback=callback)
                self.usb_guard.start()
            
            log_event("Комплексная защита файла активирована")
            
        except Exception as e:
            log_event(f"Ошибка запуска защиты: {str(e)}")
            raise
    
    def stop_protection(self):
        """Остановка защиты"""
        if self.file_guard:
            self.file_guard.stop()
        
        if self.usb_guard:
            self.usb_guard.stop()
        
        log_event("Комплексная защита файла деактивирована")
    
    def is_running(self) -> bool:
        """Проверка состояния защиты"""
        file_guard_running = self.file_guard and self.file_guard.is_alive()
        usb_guard_running = self.usb_guard and self.usb_guard.is_alive()
        
        if self.enable_usb_monitoring:
            return file_guard_running and usb_guard_running
        else:
            return file_guard_running


# Пример использования
if __name__ == "__main__":
    def alert_callback(message: str):
        print(f"🚨 ТРЕВОГА: {message}")
        # Здесь можно добавить дополнительные действия:
        # - Отправка уведомления
        # - Блокировка системы
        # - Логирование в файл
    
    # Тестирование
    test_file = "test_protected_file.txt"
    
    # Создаем тестовый файл
    try:
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("Это защищенный файл для тестирования.")
        
        print(f"Создан тестовый файл: {test_file}")
        
        # Запускаем защиту
        protection = ComprehensiveFileProtection(test_file)
        protection.start_protection(callback=alert_callback)
        
        print("Защита активирована. Попробуйте изменить, переместить или скопировать файл на USB...")
        print("Нажмите Ctrl+C для остановки")
        
        # Ожидание
        try:
            while protection.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nОстановка защиты...")
            protection.stop_protection()
            
            # Удаляем тестовый файл
            if os.path.exists(test_file):
                os.remove(test_file)
                print(f"Тестовый файл {test_file} удален")
    
    except Exception as e:
        print(f"Ошибка: {e}")