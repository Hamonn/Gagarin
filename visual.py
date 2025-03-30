import os
import time
import pyperclip
import threading
import multiprocessing
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog,
                             QDialog, QSpinBox, QHBoxLayout, QLineEdit, QMessageBox, QCheckBox)
from crypto_module import CryptoModule


def delete_file_after_delay(file_path, delay):
    """Удаление файла через заданное время (фоновый процесс)."""
    time.sleep(delay)
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Файл {file_path} удалён по истечению таймера.")


def monitor_clipboard(file_path):
    """Следит за буфером обмена и удаляет файл, если его содержимое скопировано."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            decrypted_content = f.read().strip()
    except Exception as e:
        print(f"Ошибка при чтении {file_path}: {e}")
        return

    while os.path.exists(file_path):
        clipboard_content = pyperclip.paste().strip()
        if clipboard_content == decrypted_content:
            os.remove(file_path)
            pyperclip.copy("")  # Очищаем буфер обмена
            print(f"Файл {file_path} удалён из-за копирования содержимого. Буфер обмена очищен.")
            break
        time.sleep(1)


class TimerDialog(QDialog):
    """Диалоговое окно для установки таймера"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Таймер")
        self.setFixedSize(200, 100)
        layout = QVBoxLayout()

        self.timer_label = QLabel("Удалить через (сек):")
        self.timer_input = QSpinBox()
        self.timer_input.setRange(1, 3600)
        self.ok_button = QPushButton("ОК")
        self.ok_button.clicked.connect(self.accept)

        layout.addWidget(self.timer_label)
        layout.addWidget(self.timer_input)
        layout.addWidget(self.ok_button)
        self.setLayout(layout)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Программа шифрования")
        self.setFixedSize(400, 350)
        self.crypto = CryptoModule()

        self.delete_after = 10  # Таймер по умолчанию (10 сек)
        self.enable_copy_protection = False  # Защита от копирования (по умолчанию выключена)

        layout = QVBoxLayout()

        # Кнопка настроек
        self.settings_button = QPushButton("⚙️ Настройки")
        self.settings_button.clicked.connect(self.open_settings)

        # Кнопка установки таймера
        self.timer_button = QPushButton("⏳ Установить таймер")
        self.timer_button.clicked.connect(self.set_timer)

        # Выбор файла
        file_layout = QHBoxLayout()
        self.file_label = QLabel("Выберите файл")
        self.file_button = QPushButton("...")
        self.file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_button)

        # Поле для пароля
        password_layout = QHBoxLayout()
        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.check_ready)
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)

        # Кнопки шифрования и дешифрования
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("🔒 Зашифровать")
        self.encrypt_button.setEnabled(False)
        self.encrypt_button.clicked.connect(self.encrypt_file)

        self.decrypt_button = QPushButton("🔓 Расшифровать")
        self.decrypt_button.setEnabled(False)
        self.decrypt_button.clicked.connect(self.decrypt_file)

        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)

        layout.addWidget(self.settings_button)
        layout.addWidget(self.timer_button)
        layout.addLayout(file_layout)
        layout.addLayout(password_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def open_settings(self):
        """Открытие диалогового окна с настройками"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройки")
        layout = QVBoxLayout()

        self.copy_protection_checkbox = QCheckBox("Включить защиту от копирования")
        self.copy_protection_checkbox.setChecked(self.enable_copy_protection)

        save_button = QPushButton("Сохранить")
        save_button.clicked.connect(lambda: self.save_settings(dialog))

        layout.addWidget(self.copy_protection_checkbox)
        layout.addWidget(save_button)
        dialog.setLayout(layout)
        dialog.exec()

    def save_settings(self, dialog):
        """Сохранение настроек чекбокса защиты от копирования"""
        self.enable_copy_protection = self.copy_protection_checkbox.isChecked()
        dialog.accept()

    def set_timer(self):
        """Открытие окна для выбора времени удаления"""
        dialog = TimerDialog()
        if dialog.exec():
            self.delete_after = dialog.timer_input.value()
            QMessageBox.information(self, "Таймер установлен", f"Файл будет удалён через {self.delete_after} сек.")

    def select_file(self):
        """Выбор файла пользователем"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.file_label.setText(file_path)
            self.check_ready()

    def check_ready(self):
        """Активирует кнопки, если файл и пароль выбраны"""
        file_selected = self.file_label.text() != "Выберите файл"
        password_entered = bool(self.password_input.text())

        self.encrypt_button.setEnabled(file_selected and password_entered)
        self.decrypt_button.setEnabled(file_selected and password_entered and self.file_label.text().endswith(".enc"))

    def encrypt_file(self):
        """Шифрование файла через crypto_module"""
        file_path = self.file_label.text()
        password = self.password_input.text()

        try:
            encrypted_file = self.crypto.encrypt_file(file_path, password)
            QMessageBox.information(self, "Готово", f"Файл зашифрован: {encrypted_file}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def decrypt_file(self):
        """Расшифровка файла через crypto_module с учётом включенных функций"""
        file_path = self.file_label.text()
        password = self.password_input.text()

        try:
            decrypted_file = self.crypto.decrypt_file(file_path, password)
            QMessageBox.information(self, "Готово", f"Файл расшифрован: {decrypted_file}")

            # Запускаем защиту от копирования (если включено)
            if self.enable_copy_protection:
                threading.Thread(target=monitor_clipboard, args=(decrypted_file,), daemon=True).start()

            # Запускаем таймер на удаление файла (всегда)
            p = multiprocessing.Process(target=delete_file_after_delay, args=(decrypted_file, self.delete_after))
            p.start()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
