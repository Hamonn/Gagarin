from PyQt6.QtWidgets import QDialog, QTextEdit, QVBoxLayout, QPushButton
from utils import log_event

class LogViewer(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Журнал событий")
        self.resize(700, 500)
        layout = QVBoxLayout(self)
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.load_logs()
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.close)
        layout.addWidget(self.text_edit)
        layout.addWidget(close_btn)
        log_event("Открыт просмотрщик логов")

    def load_logs(self):
        try:
            with open("encryptor.log", "r", encoding="utf-8") as f:
                self.text_edit.setText(f.read())
        except FileNotFoundError:
            self.text_edit.setText("Журнал событий пуст.")
            log_event("Файл логов не найден")
        except Exception as e:
            self.text_edit.setText(f"Ошибка загрузки логов: {str(e)}")
            log_event(f"Ошибка загрузки логов: {str(e)}")