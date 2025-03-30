import os
import sys
import multiprocessing
import ctypes
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog,
                             QDialog, QSpinBox, QHBoxLayout, QLineEdit, QMessageBox, QCheckBox, QComboBox)
from crypto_module import CryptoModule
from file_monitor import start_monitoring
from device_checker import get_device_id, get_ip_address


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)


class SettingsDialog(QDialog):
    def __init__(self, current_timer, copy_protection, encryption_method, max_opens, max_attempts, device_restriction):
        super().__init__()
        self.setWindowTitle("Настройки")
        self.setFixedSize(300, 350)
        layout = QVBoxLayout()

        timer_layout = QHBoxLayout()
        self.timer_label = QLabel("Удалить через (сек):")
        self.timer_input = QSpinBox()
        self.timer_input.setRange(1, 3600)
        self.timer_input.setValue(current_timer)
        timer_layout.addWidget(self.timer_label)
        timer_layout.addWidget(self.timer_input)

        self.copy_protection_checkbox = QCheckBox("Защита от копирования")
        self.copy_protection_checkbox.setChecked(copy_protection)

        self.device_restriction_checkbox = QCheckBox("Привязка к устройству")
        self.device_restriction_checkbox.setChecked(device_restriction)

        encryption_layout = QHBoxLayout()
        self.encryption_label = QLabel("Метод шифрования:")
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(["AES-256-CBC", "ChaCha20", "Blowfish"])
        self.encryption_combo.setCurrentText(encryption_method)
        encryption_layout.addWidget(self.encryption_label)
        encryption_layout.addWidget(self.encryption_combo)

        opens_layout = QHBoxLayout()
        self.opens_label = QLabel("Макс. открытий:")
        self.opens_input = QSpinBox()
        self.opens_input.setRange(1, 100)
        self.opens_input.setValue(max_opens)
        opens_layout.addWidget(self.opens_label)
        opens_layout.addWidget(self.opens_input)

        attempts_layout = QHBoxLayout()
        self.attempts_label = QLabel("Макс. неверных попыток:")
        self.attempts_input = QSpinBox()
        self.attempts_input.setRange(1, 10)
        self.attempts_input.setValue(max_attempts)
        attempts_layout.addWidget(self.attempts_label)
        attempts_layout.addWidget(self.attempts_input)

        self.save_button = QPushButton("Сохранить")
        self.save_button.clicked.connect(self.accept)

        layout.addLayout(timer_layout)
        layout.addWidget(self.copy_protection_checkbox)
        layout.addWidget(self.device_restriction_checkbox)
        layout.addLayout(encryption_layout)
        layout.addLayout(opens_layout)
        layout.addLayout(attempts_layout)
        layout.addWidget(self.save_button)
        self.setLayout(layout)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Программа шифрования")
        self.setFixedSize(400, 300)
        self.crypto = CryptoModule()
        self.observers = []

        self.delete_after = 10
        self.enable_copy_protection = False
        self.encryption_method = "AES-256-CBC"
        self.max_opens = 5
        self.max_attempts = 3
        self.device_restriction = False
        self.device_id = get_device_id() if self.device_restriction else None
        self.ip_address = get_ip_address() if self.device_restriction else None

        layout = QVBoxLayout()

        self.settings_button = QPushButton("⚙️ Настройки")
        self.settings_button.clicked.connect(self.open_settings)

        file_layout = QHBoxLayout()
        self.file_label = QLabel("Выберите файл")
        self.file_button = QPushButton("...")
        self.file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_button)

        password_layout = QHBoxLayout()
        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.check_ready)
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)

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
        layout.addLayout(file_layout)
        layout.addLayout(password_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def open_settings(self):
        dialog = SettingsDialog(self.delete_after, self.enable_copy_protection, self.encryption_method, self.max_opens, self.max_attempts, self.device_restriction)
        if dialog.exec():
            self.delete_after = dialog.timer_input.value()
            self.enable_copy_protection = dialog.copy_protection_checkbox.isChecked()
            self.device_restriction = dialog.device_restriction_checkbox.isChecked()
            self.encryption_method = dialog.encryption_combo.currentText()
            self.max_opens = dialog.opens_input.value()
            self.max_attempts = dialog.attempts_input.value()
            self.device_id = get_device_id() if self.device_restriction else None
            self.ip_address = get_ip_address() if self.device_restriction else None
            QMessageBox.information(self, "Настройки сохранены",
                                    f"Таймер: {self.delete_after} сек\n"
                                    f"Защита от копирования: {'Вкл' if self.enable_copy_protection else 'Выкл'}\n"
                                    f"Привязка к устройству: {'Вкл' if self.device_restriction else 'Выкл'}\n"
                                    f"Метод шифрования: {self.encryption_method}\n"
                                    f"Макс. открытий: {self.max_opens}\n"
                                    f"Макс. попыток: {self.max_attempts}")

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "Выберите файл",
            "",
            "All Files (*);;Text Files (*.txt);;Word Documents (*.doc *.docx);;PDF Files (*.pdf);;ZIP Files (*.zip)"
        )
        if file_path:
            self.file_label.setText(file_path)
            self.check_ready()

    def check_ready(self):
        file_selected = self.file_label.text() != "Выберите файл"
        password_entered = bool(self.password_input.text())
        self.encrypt_button.setEnabled(file_selected and password_entered)
        self.decrypt_button.setEnabled(file_selected and password_entered and self.file_label.text().endswith(".enc"))

    def encrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text()

        try:
            encrypted_file = self.crypto.encrypt_file(file_path, password, method=self.encryption_method,
                                                      max_opens=self.max_opens, max_attempts=self.max_attempts,
                                                      device_id=self.device_id, ip_address=self.ip_address)
            QMessageBox.information(self, "Готово", f"Файл зашифрован: {encrypted_file}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def decrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text()

        try:
            decrypted_file_path = QFileDialog.getSaveFileName(
                self,
                "Сохранить расшифрованный файл",
                os.path.splitext(file_path)[0],
                "All Files (*)"
            )[0]
            if not decrypted_file_path:
                return

            decrypted_file = self.crypto.decrypt_file(file_path, password, method=self.encryption_method,
                                                     output_path=decrypted_file_path,
                                                     current_device_id=self.device_id if self.device_restriction else None,
                                                     current_ip=self.ip_address if self.device_restriction else None)
            observer = start_monitoring(self.crypto, file_path, decrypted_file, password, self.encryption_method,
                                        self.delete_after, self.enable_copy_protection, self.max_opens)
            self.observers.append(observer)

            QMessageBox.information(self, "Готово", f"Файл расшифрован: {decrypted_file}")

        except PermissionError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def closeEvent(self, event):
        for observer in self.observers:
            observer.stop()
        for observer in self.observers:
            observer.join()
        event.accept()


if __name__ == "__main__":
    run_as_admin()  # Запрос прав администратора при запуске
    multiprocessing.freeze_support()
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()