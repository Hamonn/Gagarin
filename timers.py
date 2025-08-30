import time
import os
import multiprocessing
from utils import secure_delete_file, log_event

class TimerProcess(multiprocessing.Process):
    def __init__(self, delay, paths):
        super().__init__()
        self.delay = delay
        self.paths = paths

    def run(self):
        time.sleep(self.delay)
        for path in self.paths:
            try:
                if path and os.path.exists(path):
                    secure_delete_file(path)
                    log_event(f"Файл удален по таймеру: {path}")
            except Exception as e:
                log_event(f"Ошибка при удалении файла {path}: {str(e)}")