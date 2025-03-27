from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog,
                             QComboBox, QCheckBox, QDialog, QSpinBox, QHBoxLayout, QLineEdit, QMessageBox)
from crypto_module import CryptoModule  # Импортируем модуль шифрования


class TimerDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Таймер")
        self.setFixedSize(200, 100)
        layout = QVBoxLayout()

        self.timer_label = QLabel("Установите время (сек):")
        self.timer_input = QSpinBox()
        self.timer_input.setRange(1, 3600)
        self.ok_button = QPushButton("ОК")
        self.ok_button.clicked.connect(self.accept)

        layout.addWidget(self.timer_label)
        layout.addWidget(self.timer_input)
        layout.addWidget(self.ok_button)
        self.setLayout(layout)


class SettingsWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Дополнительные настройки")
        self.setFixedSize(300, 200)
        layout = QVBoxLayout()

        self.checkbox1 = QCheckBox("Защита от копирования")
        self.checkbox2 = QCheckBox("Дополнительная функция 1")
        self.checkbox3 = QCheckBox("Дополнительная функция 2")

        self.back_button = QPushButton("Назад")
        self.back_button.clicked.connect(self.close)

        layout.addWidget(self.checkbox1)
        layout.addWidget(self.checkbox2)
        layout.addWidget(self.checkbox3)
        layout.addWidget(self.back_button)
        self.setLayout(layout)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Программа шифрования")
        self.setFixedSize(350, 500)
        self.crypto = CryptoModule()  # Экземпляр модуля шифрования

        layout = QVBoxLayout()

        self.file_label = QLabel("Выберите файл")
        file_layout = QHBoxLayout()
        self.file_button = QPushButton("...")
        self.file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_button)

        self.encrypt_method = QComboBox()
        self.encrypt_method.addItems(["AES", "RSA", "SHA-256"])
        self.encrypt_method.setPlaceholderText("Выберите метод шифрования")
        self.encrypt_method.currentIndexChanged.connect(self.check_ready)

        password_layout = QHBoxLayout()
        self.password_label = QLabel("Введите пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.check_ready)
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)

        self.timer_button = QPushButton("Таймер")
        self.timer_button.clicked.connect(self.set_timer)

        self.settings_button = QPushButton("Дополнительные настройки")
        self.settings_button.clicked.connect(self.open_settings)

        self.encrypt_button = QPushButton("Зашифровать файл")
        self.encrypt_button.setEnabled(False)
        self.encrypt_button.clicked.connect(self.encrypt_file)

        layout.addLayout(file_layout)
        layout.addWidget(self.encrypt_method)
        layout.addLayout(password_layout)
        layout.addWidget(self.timer_button)
        layout.addWidget(self.settings_button)
        layout.addWidget(self.encrypt_button)
        self.setLayout(layout)

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.file_label.setText(file_path)
            self.check_ready()

    def set_timer(self):
        dialog = TimerDialog()
        if dialog.exec():
            print(f"Таймер установлен на {dialog.timer_input.value()} секунд")

    def open_settings(self):
        self.settings_window = SettingsWindow()
        self.settings_window.show()

    def check_ready(self):
        if (self.file_label.text() != "Выберите файл" and
                self.encrypt_method.currentText() and
                self.password_input.text()):
            self.encrypt_button.setEnabled(True)
        else:
            self.encrypt_button.setEnabled(False)

    def encrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text()

        if file_path == "Выберите файл" or not password:
            QMessageBox.warning(self, "Ошибка", "Выберите файл и введите пароль")
            return

        try:
            encrypted_file = self.crypto.encrypt_file(file_path, password)
            QMessageBox.information(self, "Готово", f"Файл зашифрован: {encrypted_file}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
