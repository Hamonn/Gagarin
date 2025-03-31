import os
import datetime

LOG_FILE_PATH = "logs.log"

def log_event(event_type, file_path="", message=""):
    try:
        with open(LOG_FILE_PATH, 'a', encoding='utf-8') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{timestamp}] [{event_type}] {file_path} {message}\n"
            f.write(line)
    except Exception as e:
        print(f"Ошибка логирования: {e}")

def read_logs():
    try:
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
                return f.readlines()
        else:
            return []
    except Exception as e:
        print(f"Ошибка чтения логов: {e}")
        return []

def clear_logs():
    try:
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write("")
            return True
    except Exception as e:
        log_event("Ошибка очистки логов", LOG_FILE_PATH, str(e))
    return False