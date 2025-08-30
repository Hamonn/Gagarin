import os
import hashlib
import psutil
import datetime

def secure_delete_file(file_path):
    try:
        with open(file_path, 'rb+') as f:
            length = os.path.getsize(file_path)
            f.write(os.urandom(length))
        os.remove(file_path)
        log_event(f"Файл безопасно удален: {file_path}")
    except Exception as e:
        log_event(f"Ошибка при безопасном удалении файла {file_path}: {str(e)}")

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        log_event(f"Ошибка вычисления хэша файла {file_path}: {str(e)}")
        return None

def get_file_drive(file_path):
    try:
        return os.path.splitdrive(os.path.abspath(file_path))[0]
    except Exception as e:
        log_event(f"Ошибка получения диска для файла {file_path}: {str(e)}")
        return None

def kill_processes_with_cmdline_reference_to_file(file_path):
    abs_path = os.path.abspath(file_path)
    abs_path_lower = abs_path.lower()
    killed = set()

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = ' '.join(proc.info['cmdline'] or []).lower()
            if abs_path_lower in cmd:
                proc.kill()
                killed.add(proc.pid)
                log_event(f"Завершен процесс {proc.name()} (PID {proc.pid}) для файла {file_path}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            log_event(f"Ошибка при завершении процесса для файла {file_path}: {str(e)}")
    return killed

def log_event(message):
    with open("encryptor.log", "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")