from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from utils import log_event

class ClipboardProtector:
    def __init__(self, parent, callback):
        self.parent = parent
        self.callback = callback
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_clipboard)
        self.timer.start(1000)
        log_event("ClipboardProtector запущен")

    def check_clipboard(self):
        clipboard = QApplication.clipboard()
        if clipboard.text() or clipboard.mimeData().hasImage():
            self.callback()
            log_event("Обнаружено копирование в буфер обмена")

    def clear(self):
        clipboard = QApplication.clipboard()
        clipboard.clear()
        self.timer.stop()
        log_event("Буфер обмена очищен и ClipboardProtector остановлен")