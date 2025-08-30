import os
import sys
import json
import ctypes
import winreg
import urllib.request
import multiprocessing
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog,
    QLineEdit, QTabWidget, QComboBox, QSpinBox, QCheckBox, QMessageBox, QGroupBox, QGridLayout, QDialog
)
from PyQt6.QtCore import QTimer
from crypto_module import CryptoModule
from device_checker import get_device_id, get_ip_address
from clipboard_protector import ClipboardProtector
from log_viewer import LogViewer
from utils import secure_delete_file, calculate_file_hash, get_file_drive, log_event
from guards import USBFileGuard, FileGuard
from timers import TimerProcess
from widgets import DropFrame, IPMACDialog
from mail_client import InternalMailClient
from database import Database

CONFIG_PATH = "config.json"
LIGHT_THEME = """
QWidget { background-color: #f5f6f5; color: #2e2e2e; font-family: Roboto; font-size: 13pt; }
QPushButton { background-color: #0288d1; color: white; padding: 12px 24px; border: none; border-radius: 8px; transition: background-color 0.2s; }
QPushButton:hover { background-color: #0277bd; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: #ffffff; color: #2e2e2e; border: 1px solid #b0bec5; border-radius: 8px; padding: 10px; }
QTabBar::tab { background: #e0e0e0; padding: 14px 28px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
QTabBar::tab:selected { background: #f5f6f5; font-weight: bold; }
QLabel { font-weight: 500; color: #455a64; }
QGroupBox { border: 1px solid #b0bec5; border-radius: 8px; padding: 14px; margin-top: 14px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 10px; }
"""

DARK_THEME = """
QWidget { background-color: #263238; color: #eceff1; font-family: Roboto; font-size: 13pt; }
QPushButton { background-color: #0288d1; color: white; padding: 12px 24px; border: none; border-radius: 8px; transition: background-color 0.2s; }
QPushButton:hover { background-color: #039be5; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: #37474f; color: #eceff1; border: 1px solid #546e7a; border-radius: 8px; padding: 10px; }
QTabBar::tab { background: #37474f; padding: 14px 28px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
QTabBar::tab:selected { background: #263238; font-weight: bold; }
QLabel { font-weight: 500; color: #b0bec5; }
QGroupBox { border: 1px solid #546e7a; border-radius: 8px; padding: 14px; margin-top: 14px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 10px; }
"""

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Авторизация")
        self.resize(400, 300)
        self.setStyleSheet(LIGHT_THEME)

        layout = QVBoxLayout()

        self.username = QLineEdit()
        self.username.setPlaceholderText("Имя пользователя")
        self.username.setToolTip("Введите уникальное имя пользователя")

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Пароль")
        self.password.setToolTip("Введите пароль (минимум 8 символов)")

        login_btn = QPushButton("Войти")
        login_btn.setToolTip("Войти в систему")
        login_btn.clicked.connect(self.login)

        register_btn = QPushButton("Регистрация")
        register_btn.setToolTip("Создать новый аккаунт")
        register_btn.clicked.connect(self.register)

        layout.addWidget(QLabel("Имя пользователя:"))
        layout.addWidget(self.username)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password)
        layout.addWidget(login_btn)
        layout.addWidget(register_btn)
        layout.addStretch()

        self.setLayout(layout)

    def login(self):
        username = self.username.text()
        password = self.password.text()
        if not username or not password:
            QMessageBox.critical(self, "Ошибка", "Заполните все поля")
            log_event(f"Попытка входа с пустыми полями: username={username}")
            return

        db = Database()
        if db.validate_user(username, password):
            log_event(f"Успешный вход пользователя: {username}")
            self.username_value = username
            self.accept()
        else:
            log_event(f"Неуспешный вход: username={username}")
            QMessageBox.critical(self, "Ошибка", "Неверные учетные данные")

    def register(self):
        username = self.username.text()
        password = self.password.text()
        if not username or not password:
            QMessageBox.critical(self, "Ошибка", "Заполните все поля")
            log_event(f"Попытка регистрации с пустыми полями: username={username}")
            return
        if len(password) < 8:
            QMessageBox.critical(self, "Ошибка", "Пароль должен быть не короче 8 символов")
            log_event(f"Попытка регистрации с коротким паролем: username={username}")
            return

        db = Database()
        try:
            db.register_user(username, password)
            log_event(f"Успешная регистрация пользователя: {username}")
            QMessageBox.information(self, "Успех", "Пользователь зарегистрирован")
        except ValueError as e:
            log_event(f"Ошибка регистрации: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

class MainWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("🔒 Encryptor")
        self.resize(900, 700)
        self.theme = "Светлая"
        self.encryption_method = "AES-256-GCM"
        self.timer_seconds = 300
        self.copy_protection = False
        self.use_ip_mac = False
        self.max_opens = 5
        self.decrypted_file_path = None
        self.encrypted_file_path = None
        self.clipboard = None
        self.load_config()
        self.apply_theme()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.encryption_tab(), "🔐 Шифрование")
        self.tabs.addTab(self.decryption_tab(), "🔓 Расшифровка")
        self.tabs.addTab(self.mail_tab(), "📧 Внутренняя почта")
        self.tabs.addTab(self.inbox_tab(), "📥 Входящие")
        self.tabs.addTab(self.program_settings_tab(), "⚙ Настройки")
        layout.addWidget(self.tabs)

    def encryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        enc_group = QGroupBox("Шифрование файла")
        enc_layout = QGridLayout(enc_group)

        self.enc_file_label = QLabel("Перетащите или выберите файл")
        self.enc_file_label.setToolTip("Выберите файл для шифрования")
        self.enc_drop_frame = DropFrame("Перетащите файл сюда", self.set_enc_file)
        self.enc_select_btn = QPushButton("📂 Выбрать файл")
        self.enc_select_btn.setToolTip("Открыть диалог выбора файла")
        self.enc_select_btn.clicked.connect(self.select_enc_file)

        self.enc_password = QLineEdit()
        self.enc_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_password.setPlaceholderText("Введите пароль")
        self.enc_password.setToolTip("Пароль для шифрования (минимум 8 символов)")

        self.enc_method = QComboBox()
        self.enc_method.addItems(["AES-256-GCM", "ChaCha20"])
        self.enc_method.setCurrentText(self.encryption_method)
        self.enc_method.setToolTip("Выберите алгоритм шифрования")

        self.timer_spin = QSpinBox()
        self.timer_spin.setRange(0, 3600)
        self.timer_spin.setValue(self.timer_seconds)
        self.timer_spin.setSuffix(" сек")
        self.timer_spin.setToolTip("Время до автоматического удаления файла")

        self.copy_protection_cb = QCheckBox("Защита от копирования")
        self.copy_protection_cb.setChecked(self.copy_protection)
        self.copy_protection_cb.setToolTip("Запретить копирование содержимого файла")

        self.restrict_mod_cb = QCheckBox("Запретить изменение")
        self.restrict_mod_cb.setToolTip("Запретить изменение файла")

        self.restrict_move_cb = QCheckBox("Запретить перемещение")
        self.restrict_move_cb.setToolTip("Запретить перемещение файла на другой диск")

        self.bind_ip_mac_cb = QCheckBox("Привязка к IP/MAC")
        self.bind_ip_mac_cb.setChecked(self.use_ip_mac)
        self.bind_ip_mac_cb.setToolTip("Привязать файл к IP/MAC текущего устройства")
        self.bind_ip_mac_cb.stateChanged.connect(self.show_ip_mac_dialog)

        self.max_opens_spin = QSpinBox()
        self.max_opens_spin.setRange(1, 100)
        self.max_opens_spin.setValue(self.max_opens)
        self.max_opens_spin.setToolTip("Максимальное количество открытий файла")

        self.encrypt_btn = QPushButton("🔐 Зашифровать")
        self.encrypt_btn.setToolTip("Начать шифрование файла")
        self.encrypt_btn.clicked.connect(self.encrypt_file)

        enc_layout.addWidget(QLabel("Файл для шифрования:"), 0, 0)
        enc_layout.addWidget(self.enc_file_label, 0, 1)
        enc_layout.addWidget(self.enc_drop_frame, 1, 0, 1, 2)
        enc_layout.addWidget(self.enc_select_btn, 2, 0, 1, 2)
        enc_layout.addWidget(QLabel("Пароль:"), 3, 0)
        enc_layout.addWidget(self.enc_password, 3, 1)
        enc_layout.addWidget(QLabel("Метод шифрования:"), 4, 0)
        enc_layout.addWidget(self.enc_method, 4, 1)
        enc_layout.addWidget(QLabel("Таймер удаления:"), 5, 0)
        enc_layout.addWidget(self.timer_spin, 5, 1)
        enc_layout.addWidget(self.copy_protection_cb, 6, 0, 1, 2)
        enc_layout.addWidget(self.restrict_mod_cb, 7, 0, 1, 2)
        enc_layout.addWidget(self.restrict_move_cb, 8, 0, 1, 2)
        enc_layout.addWidget(self.bind_ip_mac_cb, 9, 0, 1, 2)
        enc_layout.addWidget(QLabel("Макс. количество открытий:"), 10, 0)
        enc_layout.addWidget(self.max_opens_spin, 10, 1)
        enc_layout.addWidget(self.encrypt_btn, 11, 0, 1, 2)

        layout.addWidget(enc_group)
        layout.addStretch()
        return tab

    def decryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        dec_group = QGroupBox("Расшифровка файла")
        dec_layout = QGridLayout(dec_group)

        self.dec_file_label = QLabel("Перетащите или выберите файл")
        self.dec_file_label.setToolTip("Выберите зашифрованный файл (.enc)")
        self.dec_drop_frame = DropFrame("Перетащите файл сюда", self.set_dec_file)
        self.dec_select_btn = QPushButton("📂 Выбрать файл")
        self.dec_select_btn.setToolTip("Открыть диалог выбора файла")
        self.dec_select_btn.clicked.connect(self.select_dec_file)

        self.dec_password = QLineEdit()
        self.dec_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.dec_password.setPlaceholderText("Введите пароль")
        self.dec_password.setToolTip("Пароль для расшифровки")

        self.decrypt_btn = QPushButton("🔓 Расшифровать")
        self.decrypt_btn.setToolTip("Начать расшифровку файла")
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        self.meta_info_label = QLabel("")
        self.meta_info_label.setWordWrap(True)
        self.timer_ui = QLabel("")

        dec_layout.addWidget(QLabel("Файл для расшифровки:"), 0, 0)
        dec_layout.addWidget(self.dec_file_label, 0, 1)
        dec_layout.addWidget(self.dec_drop_frame, 1, 0, 1, 2)
        dec_layout.addWidget(self.dec_select_btn, 2, 0, 1, 2)
        dec_layout.addWidget(QLabel("Пароль:"), 3, 0)
        dec_layout.addWidget(self.dec_password, 3, 1)
        dec_layout.addWidget(self.decrypt_btn, 4, 0, 1, 2)
        dec_layout.addWidget(self.meta_info_label, 5, 0, 1, 2)
        dec_layout.addWidget(self.timer_ui, 6, 0, 1, 2)

        layout.addWidget(dec_group)
        layout.addStretch()
        return tab

    def mail_tab(self):
        tab = InternalMailClient(self.username)
        return tab

    def inbox_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        inbox_group = QGroupBox("Входящие сообщения")
        inbox_layout = QVBoxLayout(inbox_group)

        self.inbox_text = InternalMailClient.create_inbox_widget(self.username)
        refresh_btn = QPushButton("🔄 Обновить")
        refresh_btn.setToolTip("Обновить список сообщений")
        refresh_btn.clicked.connect(self.inbox_text.refresh)

        inbox_layout.addWidget(refresh_btn)
        inbox_layout.addWidget(self.inbox_text)

        layout.addWidget(inbox_group)
        layout.addStretch()
        return tab

    def program_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        settings_group = QGroupBox("Настройки приложения")
        settings_layout = QGridLayout(settings_group)

        theme_box = QComboBox()
        theme_box.addItems(["Светлая", "Тёмная"])
        theme_box.setCurrentText(self.theme)
        theme_box.setToolTip("Выберите тему интерфейса")
        theme_box.currentTextChanged.connect(self.change_theme)

        autorun_btn = QPushButton("🔁 В автозагрузку")
        autorun_btn.setToolTip("Добавить приложение в автозагрузку Windows")
        autorun_btn.clicked.connect(self.set_autorun)

        admin_btn = QPushButton("🛡 Запуск от администратора")
        admin_btn.setToolTip("Перезапустить приложение с правами администратора")
        admin_btn.clicked.connect(self.run_as_admin)

        firewall_btn = QPushButton("🧱 В исключения брандмауэра")
        firewall_btn.setToolTip("Добавить приложение в исключения брандмауэра")
        firewall_btn.clicked.connect(self.add_to_firewall)

        log_view_btn = QPushButton("📜 Журнал")
        log_view_btn.setToolTip("Открыть журнал событий")
        log_view_btn.clicked.connect(self.open_log_viewer)

        license_btn = QPushButton("🧾 Лицензия")
        license_btn.setToolTip("Просмотреть информацию о лицензии")
        license_btn.clicked.connect(self.show_license)

        update_btn = QPushButton("🌍 Проверить обновления")
        update_btn.setToolTip("Проверить наличие обновлений")
        update_btn.clicked.connect(self.check_updates)

        settings_layout.addWidget(QLabel("Тема интерфейса:"), 0, 0)
        settings_layout.addWidget(theme_box, 0, 1)
        settings_layout.addWidget(autorun_btn, 1, 0, 1, 2)
        settings_layout.addWidget(admin_btn, 2, 0, 1, 2)
        settings_layout.addWidget(firewall_btn, 3, 0, 1, 2)
        settings_layout.addWidget(log_view_btn, 4, 0, 1, 2)
        settings_layout.addWidget(license_btn, 5, 0, 1, 2)
        settings_layout.addWidget(update_btn, 6, 0, 1, 2)

        layout.addWidget(settings_group)
        layout.addStretch()
        return tab

    def select_enc_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.enc_file_label.setText(os.path.basename(file_path))
            self.enc_drop_frame.label.setText(os.path.basename(file_path))
            self.enc_file_path = file_path
            log_event(f"Выбран файл для шифрования: {file_path}")

    def select_dec_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", filter="Encrypted files (*.enc)")
        if file_path:
            self.dec_file_label.setText(os.path.basename(file_path))
            self.dec_drop_frame.label.setText(os.path.basename(file_path))
            self.dec_file_path = file_path
            log_event(f"Выбран файл для расшифровки: {file_path}")

    def set_enc_file(self, path):
        self.enc_file_label.setText(os.path.basename(path))
        self.enc_drop_frame.label.setText(os.path.basename(path))
        self.enc_file_path = path
        log_event(f"Перетащен файл для шифрования: {path}")

    def set_dec_file(self, path):
        self.dec_file_label.setText(os.path.basename(path))
        self.dec_drop_frame.label.setText(os.path.basename(path))
        self.dec_file_path = path
        log_event(f"Перетащен файл для расшифровки: {path}")

    def show_ip_mac_dialog(self):
        if self.bind_ip_mac_cb.isChecked():
            dialog = IPMACDialog(self)
            if dialog.exec():
                ip, mac = dialog.get_values()
                self.ip_address = ip
                self.mac_address = mac
                log_event(f"Установлены IP/MAC: {ip}/{mac}")
            else:
                self.bind_ip_mac_cb.setChecked(False)
                log_event("Отменена привязка к IP/MAC")

    def encrypt_file(self):
        if not hasattr(self, 'enc_file_path') or not self.enc_file_path:
            QMessageBox.critical(self, "Ошибка", "Выберите файл для шифрования")
            log_event("Попытка шифрования без выбранного файла")
            return

        password = self.enc_password.text()
        if not password or len(password) < 8:
            QMessageBox.critical(self, "Ошибка", "Введите пароль (минимум 8 символов)")
            log_event("Попытка шифрования с пустым или коротким паролем")
            return

        try:
            crypto = CryptoModule()
            options = {
                "method": self.enc_method.currentText(),
                "timer_seconds": self.timer_spin.value(),
                "copy_protection": self.copy_protection_cb.isChecked(),
                "bind_to_ip_mac": self.bind_ip_mac_cb.isChecked(),
                "device_id": get_device_id(),
                "ip_address": getattr(self, 'ip_address', get_ip_address()),
                "mac_address": getattr(self, 'mac_address', None),
                "max_opens": self.max_opens_spin.value(),
                "restrict_modification": self.restrict_mod_cb.isChecked(),
                "restrict_move": self.restrict_move_cb.isChecked()
            }
            out_path = crypto.encrypt_file(self.enc_file_path, password, **options)
            log_event(f"Файл зашифрован: {out_path}")
            QMessageBox.information(self, "Успех", f"Файл зашифрован: {out_path}\nОтправьте его через вкладку 'Внутренняя почта'.")
            self.tabs.setCurrentIndex(2)
            self.mail_tab().set_attachment(out_path)
            self.enc_file_label.setText("Файл не выбран")
            self.enc_drop_frame.label.setText("Перетащите файл сюда")
            self.enc_file_path = None
        except Exception as e:
            log_event(f"Ошибка шифрования: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

    def decrypt_file(self):
        if not hasattr(self, 'dec_file_path') or not self.dec_file_path:
            QMessageBox.critical(self, "Ошибка", "Выберите файл для расшифровки")
            log_event("Попытка расшифровки без выбранного файла")
            return

        password = self.dec_password.text()
        if not password:
            QMessageBox.critical(self, "Ошибка", "Введите пароль")
            log_event("Попытка расшифровки с пустым паролем")
            return

        try:
            crypto = CryptoModule()
            output_path = os.path.splitext(self.dec_file_path)[0]
            output_path, meta = crypto.decrypt_file(self.dec_file_path, password, output_path)

            self.decrypted_file_path = output_path
            self.encrypted_file_path = self.dec_file_path

            self.meta_info_label.setText(
                f"Осталось открытий: {meta['max_opens'] - meta['current_opens']}\n"
                f"Таймер: {meta['timer']} сек\n"
                f"Защита от копирования: {'вкл' if meta['copy_protection'] else 'выкл'}\n"
                f"Привязка к IP/MAC: {'вкл' if meta['bind'] else 'выкл'}\n"
                f"Запрет изменения: {'вкл' if meta['restrict_modification'] else 'выкл'}\n"
                f"Запрет перемещения: {'вкл' if meta['restrict_move'] else 'выкл'}"
            )

            if meta.get('copy_protection'):
                self.clipboard = ClipboardProtector(self, self.handle_clipboard_violation)
                self.usb_guard = USBFileGuard(self.decrypted_file_path, self.handle_violation)
                self.usb_guard.start()

            if meta.get('restrict_move') or meta.get('restrict_modification'):
                original_hash = calculate_file_hash(self.decrypted_file_path) if meta.get('restrict_modification') else None
                allow_drive = get_file_drive(self.decrypted_file_path) if meta.get('restrict_move') else None
                self.file_guard = FileGuard(self.decrypted_file_path, allow_drive, original_hash, self.handle_violation)
                self.file_guard.start()

            if meta.get('timer') > 0:
                self.start_timer(meta['timer'])

            log_event(f"Файл расшифрован: {output_path}")
            QMessageBox.information(self, "Успех", f"Файл расшифрован: {output_path}")
        except Exception as e:
            log_event(f"Ошибка расшифровки: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

    def start_timer(self, seconds):
        self.remaining = seconds
        self.timer_ui.setText(f"⏳ До удаления: {self.remaining} сек")

        self.timer_countdown = QTimer(self)
        self.timer_countdown.timeout.connect(self.update_timer)
        self.timer_countdown.start(1000)

        self.delete_timer_process = TimerProcess(
            seconds,
            [self.decrypted_file_path, self.encrypted_file_path]
        )
        self.delete_timer_process.daemon = True
        self.delete_timer_process.start()
        log_event(f"Запущен таймер удаления на {seconds} сек")

    def handle_violation(self, message="Обнаружено нарушение безопасности."):
        for p in [self.decrypted_file_path, self.encrypted_file_path]:
            try:
                if p and os.path.exists(p):
                    secure_delete_file(p)
            except:
                pass

        if self.clipboard:
            self.clipboard.clear()

        if hasattr(self, 'file_guard'):
            self.file_guard.stop()

        if hasattr(self, 'usb_guard'):
            self.usb_guard.stop()

        if hasattr(self, 'delete_timer_process') and self.delete_timer_process.is_alive():
            self.delete_timer_process.terminate()

        self.meta_info_label.setText(f"❌ {message}\nФайлы удалены.")
        self.timer_ui.setText("")
        self.dec_file_label.setText("Файл не выбран")
        self.tabs.setCurrentIndex(0)

        log_event(f"Нарушение безопасности: {message}")
        self.decrypted_file_path = None
        self.encrypted_file_path = None

    def destroy_files(self):
        for path in (self.decrypted_file_path, self.encrypted_file_path):
            try:
                if path and os.path.exists(path):
                    secure_delete_file(path)
            except:
                pass

        if self.clipboard:
            self.clipboard.clear()

        if hasattr(self, 'file_guard'):
            self.file_guard.stop()

        if hasattr(self, 'usb_guard'):
            self.usb_guard.stop()

        if hasattr(self, 'delete_timer_process') and self.delete_timer_process.is_alive():
            self.delete_timer_process.terminate()

        self.meta_info_label.setText("❌ Файлы удалены по таймеру или из-за нарушения.")
        self.timer_ui.setText("")
        self.dec_file_label.setText("Файл не выбран")
        self.tabs.setCurrentIndex(0)

        log_event("Файлы удалены по таймеру или нарушению")
        self.decrypted_file_path = None
        self.encrypted_file_path = None

    def update_timer(self):
        self.remaining -= 1
        if self.remaining <= 0:
            self.timer_countdown.stop()
            self.timer_ui.setText("⏳ Файл будет удалён...")
        else:
            self.timer_ui.setText(f"⏳ До удаления: {self.remaining} сек")

    def handle_clipboard_violation(self):
        if self.clipboard:
            self.clipboard.clear()

        for p in [self.decrypted_file_path, self.encrypted_file_path]:
            try:
                if p and os.path.exists(p):
                    secure_delete_file(p)
            except:
                pass

        if hasattr(self, 'file_guard'):
            self.file_guard.stop()

        if hasattr(self, 'delete_timer_process') and self.delete_timer_process.is_alive():
            self.delete_timer_process.terminate()

        self.meta_info_label.setText("❌ Обнаружено копирование. Файлы удалены.")
        self.timer_ui.setText("")
        self.dec_file_label.setText("Файл не выбран")
        self.tabs.setCurrentIndex(0)

        log_event("Обнаружено копирование, файлы удалены")
        self.decrypted_file_path = None
        self.encrypted_file_path = None

    def add_to_firewall(self):
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Encryptor", "dir=in", "action=allow",
                f"program={sys.executable}", "enable=yes"
            ], check=True)
            log_event("Добавлено в исключения брандмауэра")
            QMessageBox.information(self, "Брандмауэр", "Добавлено в исключения")
        except Exception as e:
            log_event(f"Ошибка добавления в брандмауэр: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

    def open_log_viewer(self):
        viewer = LogViewer()
        viewer.exec()

    def change_theme(self, theme):
        self.theme = theme
        self.apply_theme()
        self.save_config()
        self.repaint()
        log_event(f"Изменена тема на: {theme}")

    def apply_theme(self):
        self.setStyleSheet(LIGHT_THEME if self.theme == "Светлая" else DARK_THEME)

    def set_autorun(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "EncryptorApp", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            log_event("Добавлено в автозагрузку")
            QMessageBox.information(self, "OK", "Добавлено в автозагрузку")
        except Exception as e:
            log_event(f"Ошибка добавления в автозагрузку: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

    def run_as_admin(self):
        log_event("Запрошен запуск от администратора")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    def show_license(self):
        log_event("Просмотр лицензии")
        QMessageBox.information(self, "Лицензия", "Лицензия: MIT\n© 2025 Encryptor Team")

    def check_updates(self):
        try:
            with urllib.request.urlopen("https://example.com/update") as response:
                data = response.read().decode()
                log_event("Проверка обновлений выполнена")
                QMessageBox.information(self, "Обновления", data or "Нет обновлений")
        except Exception as e:
            log_event(f"Ошибка проверки обновлений: {str(e)}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось проверить обновления: {e}")

    def save_config(self):
        cfg = {
            "theme": self.theme,
            "encryption_method": self.encryption_method,
            "timer": self.timer_seconds,
            "copy_protection": self.copy_protection,
            "bind": self.use_ip_mac,
            "max_opens": self.max_opens
        }
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            log_event("Конфигурация сохранена")
        except Exception as e:
            log_event(f"Ошибка сохранения конфигурации: {str(e)}")

    def load_config(self):
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    self.theme = cfg.get("theme", self.theme)
                    self.encryption_method = cfg.get("encryption_method", self.encryption_method)
                    self.timer_seconds = cfg.get("timer", self.timer_seconds)
                    self.copy_protection = cfg.get("copy_protection", self.copy_protection)
                    self.use_ip_mac = cfg.get("bind", self.use_ip_mac)
                    self.max_opens = cfg.get("max_opens", self.max_opens)
                log_event("Конфигурация загружена")
            except Exception as e:
                log_event(f"Ошибка загрузки конфигурации: {str(e)}")

if __name__ == '__main__':
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    login_dialog = LoginDialog()
    if login_dialog.exec() == QDialog.DialogCode.Accepted:
        window = MainWindow(login_dialog.username_value)
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)