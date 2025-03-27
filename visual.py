from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog,
                             QComboBox, QCheckBox, QDialog, QSpinBox, QHBoxLayout, QLineEdit, QMessageBox)
from PyQt6.QtCore import QTimer
import os
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

        self.encrypt_button = QPushButton("🔒 Зашифровать файл")
        self.encrypt_button.setEnabled(False)
        self.encrypt_button.clicked.connect(self.encrypt_file)

        self.decrypt_button = QPushButton("🔓 Расшифровать файл")
        self.decrypt_button.setEnabled(False)
        self.decrypt_button.clicked.connect(self.decrypt_file)

        layout.addLayout(file_layout)
        layout.addWidget(self.encrypt_method)
        layout.addLayout(password_layout)
        layout.addWidget(self.timer_button)
        layout.addWidget(self.settings_button)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        self.setLayout(layout)

        self.timer_duration = 0  # Время удаления зашифрованного файла
        self.timer = QTimer()
        self.timer.timeout.connect(self.delete_encrypted_file)
        self.encrypted_file_path = ""  # Путь к зашифрованному файлу

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.file_label.setText(file_path)
            self.check_ready()

    def set_timer(self):
        """Устанавливает таймер удаления зашифрованного файла"""
        dialog = TimerDialog()
        if dialog.exec():
            self.timer_duration = dialog.timer_input.value()
            QMessageBox.information(self, "Таймер", f"Зашифрованный файл будет удалён через {self.timer_duration} секунд")

    def open_settings(self):
        self.settings_window = SettingsWindow()
        self.settings_window.show()

    def check_ready(self):
        """Активирует кнопки только если все условия выполнены"""
        file_selected = self.file_label.text() != "Выберите файл"
        password_entered = bool(self.password_input.text())
        encryption_method_selected = bool(self.encrypt_method.currentText())

        self.encrypt_button.setEnabled(file_selected and password_entered and encryption_method_selected)
        self.decrypt_button.setEnabled(file_selected and password_entered)

    def encrypt_file(self):
        """Шифрует файл, удаляет исходный и запускает таймер удаления зашифрованного файла"""
        file_path = self.file_label.text()
        password = self.password_input.text()

        if file_path == "Выберите файл" or not password:
            QMessageBox.warning(self, "Ошибка", "Выберите файл и введите пароль")
            return

        try:
            self.encrypted_file_path = self.crypto.encrypt_file(file_path, password)
            QMessageBox.information(self, "Готово", f"Файл зашифрован: {self.encrypted_file_path}")

            # Удаляем исходный файл после успешного шифрования
            if os.path.exists(file_path):
                os.remove(file_path)
                QMessageBox.information(self, "Удаление", "Исходный файл был удалён")

            # Запускаем таймер удаления зашифрованного файла
            if self.timer_duration > 0:
                self.timer.start(self.timer_duration * 1000)  # Запуск таймера

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def delete_encrypted_file(self):
        """Удаляет зашифрованный файл по таймеру"""
        self.timer.stop()  # Останавливаем таймер

        if self.encrypted_file_path and os.path.exists(self.encrypted_file_path):
            os.remove(self.encrypted_file_path)
            QMessageBox.information(self, "Удаление", "Зашифрованный файл был удалён")
            self.encrypted_file_path = ""  # Очищаем путь

    def decrypt_file(self):
        """Расшифровывает файл, но не удаляет зашифрованную версию"""
        file_path = self.file_label.text()
        password = self.password_input.text()

        if file_path == "Выберите файл" or not password:
            QMessageBox.warning(self, "Ошибка", "Выберите зашифрованный файл и введите пароль")
            return

        if not file_path.endswith(".enc"):
            QMessageBox.warning(self, "Ошибка", "Выбранный файл не зашифрован!")
            return

        try:
            decrypted_file = self.crypto.decrypt_file(file_path, password)
            QMessageBox.information(self, "Готово", f"Файл расшифрован: {decrypted_file}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
