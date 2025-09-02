import os
import hashlib
import psutil
import datetime
import random

LOG_FILE = "encryptor.log"


def log_event(message, level="INFO"):
    """Записывает событие в лог с указанием времени и уровня"""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    except Exception:
        # Если лог не удалось записать, выводим в консоль
        print(f"[LOGGING ERROR] {message}")


def secure_delete_file(file_path, passes=3, chunk_size=1024 * 1024):
    """
    Безопасное удаление файла с многократной перезаписью.
    passes - количество перезаписей
    chunk_size - размер блока для записи
    """
    try:
        file_path = os.path.normpath(file_path)

        if not os.path.isfile(file_path):
            log_event(f"Попытка удалить несуществующий файл: {file_path}", level="WARNING")
            return False

        length = os.path.getsize(file_path)
        with open(file_path, 'rb+') as f:
            for p in range(passes):
                f.seek(0)
                total_written = 0
                while total_written < length:
                    to_write = min(chunk_size, length - total_written)
                    f.write(os.urandom(to_write))
                    total_written += to_write
                f.flush()
                os.fsync(f.fileno())
                log_event(f"Файл {file_path} перезаписан ({p + 1}/{passes})")

        os.remove(file_path)
        log_event(f"Файл безопасно удалён: {file_path}")
        return True

    except Exception as e:
        log_event(f"Ошибка при безопасном удалении файла {file_path}: {str(e)}", level="ERROR")
        return False


def calculate_file_hash(file_path, algorithm="sha256", chunk_size=4096):
    """
    Вычисляет хэш файла с использованием указанного алгоритма.
    """
    try:
        file_path = os.path.normpath(file_path)

        if not os.path.isfile(file_path):
            log_event(f"Файл для хэширования не найден: {file_path}", level="WARNING")
            return None

        try:
            hash_func = getattr(hashlib, algorithm)()
        except AttributeError:
            log_event(f"Неизвестный алгоритм хэширования: {algorithm}", level="ERROR")
            return None

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_func.update(chunk)

        digest = hash_func.hexdigest()
        log_event(f"Хэш {algorithm} для {file_path}: {digest}")
        return digest

    except Exception as e:
        log_event(f"Ошибка вычисления хэша файла {file_path}: {str(e)}", level="ERROR")
        return None


def get_file_drive(file_path):
    """
    Определяет диск/раздел, на котором находится файл.
    """
    try:
        file_path = os.path.normpath(file_path)
        drive = os.path.splitdrive(os.path.abspath(file_path))[0]
        return drive or None
    except Exception as e:
        log_event(f"Ошибка получения диска для файла {file_path}: {str(e)}", level="ERROR")
        return None


def kill_processes_with_cmdline_reference_to_file(file_path):
    """
    Завершает процессы, у которых в командной строке есть упоминание файла.
    """
    abs_path = os.path.normpath(os.path.abspath(file_path)).lower()
    killed = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline') or []
            cmd_str = " ".join(cmdline).lower()

            if abs_path in cmd_str:
                proc.kill()
                killed.append({
                    "pid": proc.pid,
                    "name": proc.info.get('name', 'Unknown'),
                    "cmdline": cmdline
                })
                log_event(f"Завершён процесс {proc.info.get('name', 'Unknown')} "
                          f"(PID {proc.pid}) для файла {file_path}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            log_event(f"Ошибка при завершении процесса для файла {file_path}: {str(e)}", level="ERROR")

    if not killed:
        log_event(f"Не найдено процессов, использующих файл: {file_path}", level="WARNING")

    return killed
