from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication
from logger import log_event

class ClipboardProtector:
    def __init__(self, parent, on_violation_callback, interval_ms=200):
        self.parent = parent
        self.clipboard = QApplication.clipboard()
        self.initial = self._capture_clipboard()
        self.on_violation = on_violation_callback

        self.timer = QTimer()
        self.timer.setInterval(interval_ms)
        self.timer.timeout.connect(self.check_clipboard)
        self.timer.start()

    def _capture_clipboard(self):
        mime = self.clipboard.mimeData()
        return {
            "text": self.clipboard.text(),
            "html": mime.html() if mime.hasHtml() else "",
            "urls": mime.urls() if mime.hasUrls() else [],
        }

    def check_clipboard(self):
        current = self._capture_clipboard()
        if (
            current["text"] != self.initial["text"]
            or current["html"] != self.initial["html"]
            or current["urls"] != self.initial["urls"]
        ):
            log_event("Буфер изменён", "clipboard", "Обнаружено копирование")
            self.timer.stop()
            self.on_violation()
