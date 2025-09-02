import time
import os
import multiprocessing
import shutil
from utils import secure_delete_file, log_event

class TimerProcess(multiprocessing.Process):
    def __init__(self, delay, paths):
        super().__init__()
        self.delay = delay
        # Приводим к списку, даже если передан один путь
        self.paths = paths if isinstance(paths, (list, tuple)) else [paths]
        self._stop_event = multiprocessing.Event()

    def stop(self):
        """Прерывает таймер, если он ещё не сработал"""
        self._stop_event.set()

    def run(self):
        log_event(f"Таймер запущен на {self.delay} сек. для {len(self.paths)} объектов")

        slept = 0
        while slept < self.delay:
            if self._stop_event.is_set():
                log_event("Таймер был остановлен пользователем")
                return
            time.sleep(1)
            slept += 1

        for path in self.paths:
            try:
                if path and os.path.exists(path):
                    if os.path.isfile(path):
                        secure_delete_file(path)
                        log_event(f"Файл удалён по таймеру: {path}")
                    elif os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                        log_event(f"Папка удалена по таймеру: {path}")
            except Exception as e:
                log_event(f"Ошибка при удалении {path}: {str(e)}")
