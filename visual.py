import os
import sys
import multiprocessing
import ctypes
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog,
    QDialog, QSpinBox, QHBoxLayout, QLineEdit, QMessageBox, QCheckBox, QComboBox,
    QGroupBox
)
from PyQt6.QtCore import QTimer
from crypto_module import CryptoModule
from file_monitor import start_monitoring
from device_checker import get_device_id, get_ip_address
from logger import log_event
from log_viewer import LogViewer
from tray_manager import TrayManager
from clipboard_protector import ClipboardProtector

DARK_THEME = """
    QWidget { background-color: #121212; color: #E0E0E0; font-family: 'Segoe UI'; font-size: 12pt; }
    QPushButton { background-color: #1E88E5; color: white; border-radius: 6px; padding: 8px 12px; border: none; }
    QPushButton:hover { background-color: #1565C0; }
    QPushButton:pressed { background-color: #0D47A1; }
    QPushButton:disabled { background-color: #555; color: #aaa; }
    QLabel { font-weight: 600; }
    QLineEdit, QSpinBox, QComboBox { background-color: #1E1E1E; color: white; border: 1px solid #333; border-radius: 6px; padding: 6px; }
    QGroupBox { border: 1px solid #444; border-radius: 8px; margin-top: 12px; padding: 8px; }
    QGroupBox:title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
"""

LIGHT_THEME = """
    QWidget { background-color: #f0f0f0; color: #202020; font-family: 'Segoe UI'; font-size: 12pt; }
    QPushButton { background-color: #0078D7; color: white; border-radius: 6px; padding: 8px 12px; border: none; }
    QPushButton:hover { background-color: #005a9e; }
    QPushButton:pressed { background-color: #004578; }
    QPushButton:disabled { background-color: #ccc; color: #666; }
    QLabel { font-weight: 600; }
    QLineEdit, QSpinBox, QComboBox { background-color: #fff; color: #000; border: 1px solid #999; border-radius: 6px; padding: 6px; }
    QGroupBox { border: 1px solid #aaa; border-radius: 8px; margin-top: 12px; padding: 8px; }
    QGroupBox:title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
"""


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
    def __init__(self, parent, current_timer, use_timer,
                 copy_protection, encryption_method, max_opens,
                 max_attempts, device_restriction):
        super().__init__(parent)
        self.setWindowTitle("⚙️ Настройки")
        self.setFixedSize(380, 460)
        self.parent = parent

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)

        # === Общие настройки ===
        general_box = QGroupBox("Общие")
        general_layout = QVBoxLayout()

        self.timer_checkbox = QCheckBox("Использовать таймер")
        self.timer_checkbox.setChecked(use_timer)
        self.timer_checkbox.stateChanged.connect(self.toggle_timer_input)

        timer_layout = QHBoxLayout()
        timer_layout.setSpacing(10)
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

        general_layout.addWidget(self.timer_checkbox)
        general_layout.addLayout(timer_layout)
        general_layout.addWidget(self.copy_protection_checkbox)
        general_layout.addWidget(self.device_restriction_checkbox)
        general_box.setLayout(general_layout)

        # === Шифрование ===
        crypto_box = QGroupBox("Шифрование")
        crypto_layout = QVBoxLayout()

        encryption_layout = QHBoxLayout()
        encryption_layout.setSpacing(10)
        self.encryption_label = QLabel("Метод:")
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(["AES-256-CBC", "ChaCha20", "Blowfish", "DES3"])
        self.encryption_combo.setCurrentText(encryption_method)
        encryption_layout.addWidget(self.encryption_label)
        encryption_layout.addWidget(self.encryption_combo)

        opens_layout = QHBoxLayout()
        opens_layout.setSpacing(10)
        self.opens_label = QLabel("Макс. открытий:")
        self.opens_input = QSpinBox()
        self.opens_input.setRange(1, 100)
        self.opens_input.setValue(max_opens)
        opens_layout.addWidget(self.opens_label)
        opens_layout.addWidget(self.opens_input)

        attempts_layout = QHBoxLayout()
        attempts_layout.setSpacing(10)
        self.attempts_label = QLabel("Макс. попыток:")
        self.attempts_input = QSpinBox()
        self.attempts_input.setRange(1, 10)
        self.attempts_input.setValue(max_attempts)
        attempts_layout.addWidget(self.attempts_label)
        attempts_layout.addWidget(self.attempts_input)

        crypto_layout.addLayout(encryption_layout)
        crypto_layout.addLayout(opens_layout)
        crypto_layout.addLayout(attempts_layout)
        crypto_box.setLayout(crypto_layout)

        # === Сохранение ===
        self.save_button = QPushButton("💾 Сохранить")
        self.save_button.clicked.connect(self.accept)

        layout.addWidget(general_box)
        layout.addWidget(crypto_box)
        layout.addStretch()
        layout.addWidget(self.save_button)
        self.setLayout(layout)

        self.apply_theme()
        self.toggle_timer_input()  # сразу обновим активность поля

    def apply_theme(self):
        theme = DARK_THEME if self.parent.current_theme == "dark" else LIGHT_THEME
        self.setStyleSheet(theme)

    def toggle_timer_input(self):
        self.timer_input.setEnabled(self.timer_checkbox.isChecked())


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Шифровальщик")
        self.setFixedSize(460, 500)
        self.crypto = CryptoModule()
        self.observers = []
        self.current_theme = "dark"

        self.use_timer = True
        self.delete_after = 10
        self.enable_copy_protection = False  # ← ВАЖНО: переместили ВЫШЕ
        self.encryption_method = "AES-256-CBC"
        self.max_opens = 5
        self.max_attempts = 3
        self.device_restriction = False
        self.device_id = get_device_id()
        self.ip_address = get_ip_address()

        # Запуск защиты только при включении
        if self.enable_copy_protection:
            self.clip_protector = ClipboardProtector(self, self.handle_clipboard_violation)
        else:
            self.clip_protector = None
            
        # Основной интерфейс
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(15, 15, 15, 15)

        self.settings_button = QPushButton("⚙️ Настройки")
        self.settings_button.clicked.connect(self.open_settings)

        self.theme_button = QPushButton("🌗 Переключить тему")
        self.theme_button.clicked.connect(self.toggle_theme)

        self.log_button = QPushButton("📜 Журнал")
        self.log_button.clicked.connect(self.open_log)

        self.clear_log_button = QPushButton("🧹 Очистить журнал")
        self.clear_log_button.clicked.connect(self.clear_logs)

        layout.addWidget(self.log_button)
        layout.addWidget(self.clear_log_button)
        layout.addWidget(self.settings_button)
        layout.addWidget(self.theme_button)

        # Группа: Файл
        file_box = QGroupBox("Файл")
        file_layout = QHBoxLayout()
        file_layout.setSpacing(10)
        self.file_label = QLabel("Выберите файл")
        self.file_button = QPushButton("📂")
        self.file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_button)
        file_box.setLayout(file_layout)
        layout.addWidget(file_box)

        # Группа: Пароль
        pass_box = QGroupBox("Пароль")
        password_layout = QHBoxLayout()
        password_layout.setSpacing(10)
        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.check_ready)
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)
        pass_box.setLayout(password_layout)
        layout.addWidget(pass_box)

        # Кнопки: шифрование/расшифровка
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("🔒 Зашифровать")
        self.encrypt_button.setEnabled(False)
        self.encrypt_button.clicked.connect(self.encrypt_file)

        self.decrypt_button = QPushButton("🔓 Расшифровать")
        self.decrypt_button.setEnabled(False)
        self.decrypt_button.clicked.connect(self.decrypt_file)

        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        layout.addSpacing(10)
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.apply_theme()

        # Трей
        self.tray = TrayManager(self)
        self.tray.show_tray()

        # Клипборд защита
        self.clip_protector = ClipboardProtector(self, self.handle_clipboard_violation)

    def apply_theme(self):
        theme = DARK_THEME if self.current_theme == "dark" else LIGHT_THEME
        self.setStyleSheet(theme)

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()

    def open_settings(self):
        dialog = SettingsDialog(self, self.delete_after, self.use_timer,
                                self.enable_copy_protection, self.encryption_method,
                                self.max_opens, self.max_attempts, self.device_restriction)
        if dialog.exec():
            self.use_timer = dialog.timer_checkbox.isChecked()
            self.delete_after = dialog.timer_input.value()
            self.enable_copy_protection = dialog.copy_protection_checkbox.isChecked()
            self.device_restriction = dialog.device_restriction_checkbox.isChecked()
            self.encryption_method = dialog.encryption_combo.currentText()
            self.max_opens = dialog.opens_input.value()
            self.max_attempts = dialog.attempts_input.value()
            self.device_id = get_device_id() if self.device_restriction else None
            self.ip_address = get_ip_address() if self.device_restriction else None

            # Перезапуск защиты от копирования
            if hasattr(self, "clip_protector") and self.clip_protector:
                self.clip_protector.timer.stop()
                self.clip_protector = None

            if self.enable_copy_protection:
                from clipboard_protector import ClipboardProtector
                self.clip_protector = ClipboardProtector(self, self.handle_clipboard_violation)


    def open_log(self):
        viewer = LogViewer()
        viewer.exec()

    def clear_logs(self):
        from logger import clear_logs
        if clear_logs():
            QMessageBox.information(self, "Журнал очищен", "Файл логов успешно очищен.")
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось очистить журнал.")

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Все файлы (*)")
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
            encrypted_file = self.crypto.encrypt_file(
                file_path, password, method=self.encryption_method,
                max_opens=self.max_opens, max_attempts=self.max_attempts,
                device_id=self.device_id, ip_address=self.ip_address
            )
            log_event("Зашифрован", file_path)
            QMessageBox.information(self, "Готово", f"Файл зашифрован: {encrypted_file}")
        except Exception as e:
            log_event("Ошибка при шифровании", file_path, str(e))
            QMessageBox.critical(self, "Ошибка", str(e))

    def decrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text()
        try:
            save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить расшифрованный файл", os.path.splitext(file_path)[0])
            if not save_path:
                return
            decrypted_file = self.crypto.decrypt_file(
                file_path, password, method=self.encryption_method,
                output_path=save_path,
                current_device_id=self.device_id if self.device_restriction else None,
                current_ip=self.ip_address if self.device_restriction else None
            )
            log_event("Расшифрован", file_path, f"Сохранено как: {decrypted_file}")
            if self.use_timer:
                observer = start_monitoring(
                    self.crypto, file_path, decrypted_file, password,
                    self.encryption_method, self.delete_after, self.max_opens
                )
                self.observers.append(observer)
            QMessageBox.information(self, "Готово", f"Файл расшифрован: {decrypted_file}")
        except (PermissionError, ValueError) as e:
            log_event("Ошибка при расшифровке", file_path, str(e))
            QMessageBox.critical(self, "Ошибка", str(e))
        except Exception as e:
            log_event("Неизвестная ошибка", file_path, str(e))
            QMessageBox.critical(self, "Ошибка", str(e))

    def handle_clipboard_violation(self):
        QMessageBox.critical(self, "Безопасность", "Обнаружено копирование! Файлы будут удалены.")

        def destroy():
            for observer in self.observers:
                if hasattr(observer, 'force_destroy'):
                    observer.force_destroy("Обнаружено копирование в буфер")
            self.observers.clear()

        import threading
        threading.Thread(target=destroy, daemon=True).start()

    def closeEvent(self, event):
        self.tray.hide_window()
        event.ignore()

if __name__ == "__main__":
    run_as_admin()
    multiprocessing.freeze_support()
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
