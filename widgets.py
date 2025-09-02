from PyQt6.QtWidgets import (
    QFrame,
    QVBoxLayout,
    QLabel,
    QDialog,
    QLineEdit,
    QPushButton
)
from PyQt6.QtGui import QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt
from utils import log_event


class DropFrame(QFrame):
    def __init__(self, label: str, callback):
        super().__init__()
        self.callback = callback

        # Метка в центре
        self.label = QLabel(label)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setWordWrap(True)

        # Основной лэйаут
        layout = QVBoxLayout(self)
        layout.addWidget(self.label)

        # Разрешаем drag & drop
        self.setAcceptDrops(True)

        # Красивое оформление
        self.setStyleSheet("""
            QFrame {
                border: 2px dashed #546e7a;
                border-radius: 8px;
                min-height: 120px;
                background-color: #eceff1;
            }
            QLabel {
                color: #37474f;
                font-size: 14px;
            }
        """)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if callable(self.callback):
                self.callback(path)
            log_event(f"Перетащен файл: {path}")


class IPMACDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Привязка к IP/MAC")
        self.resize(400, 220)

        layout = QVBoxLayout(self)

        # Поле ввода IP
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Пример: 192.168.1.100")
        self.ip_input.setToolTip("Введите IP-адрес устройства")

        # Поле ввода MAC
        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("Пример: aa:bb:cc:dd:ee:ff")
        self.mac_input.setToolTip("Введите MAC-адрес устройства")

        # Кнопка сохранения
        self.save_btn = QPushButton("Сохранить")
        self.save_btn.setToolTip("Сохранить настройки IP/MAC")
        self.save_btn.clicked.connect(self.accept)

        # Добавляем в интерфейс
        layout.addWidget(QLabel("Введите IP-адрес:"))
        layout.addWidget(self.ip_input)
        layout.addWidget(QLabel("Введите MAC-адрес:"))
        layout.addWidget(self.mac_input)
        layout.addWidget(self.save_btn)

        # Немного стиля
        self.setStyleSheet("""
            QLabel {
                font-size: 13px;
                color: #263238;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #90a4ae;
                border-radius: 4px;
            }
            QPushButton {
                background-color: #546e7a;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #455a64;
            }
        """)

    def get_values(self):
        return self.ip_input.text().strip(), self.mac_input.text().strip()
