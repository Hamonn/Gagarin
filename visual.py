import os
import time
import multiprocessing
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog,
                             QComboBox, QDialog, QSpinBox, QHBoxLayout, QLineEdit, QMessageBox)
from crypto_module import CryptoModule


def delete_file_after_delay(file_path, delay):
    """Функция для удаления файла через заданное время (фоновый процесс)."""
    time.sleep(delay)
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Файл {file_path} удалён по истечению таймера.")


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
        self.setFixedSize(400, 300)
        self.crypto = CryptoModule()
        self.delete_after = None  # Время удаления зашифрованного файла
        self.encrypted_file_path = None  # Путь к зашифрованному файлу

        layout = QVBoxLayout()

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

        # Выбор метода шифрования
        method_layout = QHBoxLayout()
        self.method_label = QLabel("Метод:")
        self.method_combo = QComboBox()
        self.method_combo.addItems(["AES", "Другой метод"])  # Можно добавить другие методы
        self.method_combo.currentIndexChanged.connect(self.check_ready)
        method_layout.addWidget(self.method_label)
        method_layout.addWidget(self.method_combo)

        # Кнопка установки таймера
        self.timer_button = QPushButton("⏳ Установить таймер")
        self.timer_button.clicked.connect(self.set_timer)

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

        layout.addLayout(file_layout)
        layout.addLayout(password_layout)
        layout.addLayout(method_layout)
        layout.addWidget(self.timer_button)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def select_file(self):
        """Выбор файла пользователем"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.file_label.setText(file_path)
            self.check_ready()

    def set_timer(self):
        """Открытие окна для выбора времени удаления"""
        dialog = TimerDialog()
        if dialog.exec():
            self.delete_after = dialog.timer_input.value()
            QMessageBox.information(self, "Таймер установлен", f"Файл будет удалён через {self.delete_after} сек.")

    def check_ready(self):
        """Активирует кнопки только если файл, пароль и метод шифрования выбраны"""
        file_selected = self.file_label.text() != "Выберите файл"
        password_entered = bool(self.password_input.text())
        method_selected = self.method_combo.currentText() != ""

        self.encrypt_button.setEnabled(file_selected and password_entered and method_selected)
        self.decrypt_button.setEnabled(file_selected and password_entered and self.file_label.text().endswith(".enc"))

    def encrypt_file(self):
        """Шифрование файла"""
        file_path = self.file_label.text()
        password = self.password_input.text()
        method = self.method_combo.currentText()

        if file_path == "Выберите файл" or not password:
            QMessageBox.warning(self, "Ошибка", "Выберите файл, метод и введите пароль")
            return

        try:
            encrypted_file = self.crypto.encrypt_file(file_path, password, method)
            self.encrypted_file_path = encrypted_file  # Сохраняем путь к зашифрованному файлу

            QMessageBox.information(self, "Готово", f"Файл зашифрован: {encrypted_file}")

            # Запускаем фоновый процесс для удаления зашифрованного файла через таймер
            if self.delete_after:
                p = multiprocessing.Process(target=delete_file_after_delay, args=(encrypted_file, self.delete_after))
                p.start()
                print(f"Файл {encrypted_file} будет удалён через {self.delete_after} секунд.")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def decrypt_file(self):
        """Расшифровка файла"""
        file_path = self.file_label.text()
        password = self.password_input.text()
        method = self.method_combo.currentText()

        if file_path == "Выберите файл" or not password:
            QMessageBox.warning(self, "Ошибка", "Выберите зашифрованный файл, метод и введите пароль")
            return

        try:
            decrypted_file = self.crypto.decrypt_file(file_path, password)
            QMessageBox.information(self, "Готово", f"Файл расшифрован: {decrypted_file}")

            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Файл {file_path} (зашифрованная версия) удалён после расшифровки.")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


if __name__ == "__main__":
    multiprocessing.freeze_support()  # Для корректной работы multiprocessing на Windows
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
