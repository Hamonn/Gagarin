from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
from logger import read_logs, clear_logs

class LogViewer(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("📜 Журнал событий")
        self.setFixedSize(600, 500)

        layout = QVBoxLayout()
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        self.refresh_button = QPushButton("🔄 Обновить")
        self.refresh_button.clicked.connect(self.load_logs)

        self.clear_button = QPushButton("🧹 Очистить")
        self.clear_button.clicked.connect(self.clear_logs)

        layout.addWidget(self.log_area)
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.clear_button)
        self.setLayout(layout)

        self.load_logs()

    def load_logs(self):
        logs = read_logs()
        self.log_area.setPlainText("".join(logs))

    def clear_logs(self):
        if clear_logs():
            self.log_area.setPlainText("")
