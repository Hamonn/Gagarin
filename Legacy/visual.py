import os
import win32file
import sys
import json
import socket
from PyQt6.QtWidgets import QDialog
import re
import multiprocessing
import threading
import time
import psutil
import subprocess
import ctypes
import winreg
import urllib.request
import webbrowser
import hashlib
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog,
    QLineEdit, QTabWidget, QTextEdit, QComboBox, QSpinBox, QCheckBox, QMessageBox, QFrame, QInputDialog
)
from PyQt6.QtGui import QGuiApplication, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt
from crypto_module import CryptoModule
from device_checker import get_device_id, get_ip_address
from clipboard_protector import ClipboardProtector
from log_viewer import LogViewer
from PyQt6.QtCore import QTimer
from multiprocessing import Process
from logger import log_event
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

CONFIG_PATH = "config.json"
LIGHT_THEME = """
QWidget { background-color: #f0f0f0; color: #202020; font-family: Segoe UI; font-size: 10pt; }
QPushButton { background-color: #0078D7; color: white; padding: 6px; border-radius: 4px; }
QPushButton:hover { background-color: #005a9e; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: white; color: black; border: 1px solid #ccc; border-radius: 4px; padding: 4px; }
QTabBar::tab { padding: 6px 12px; }
QLabel { font-weight: 500; }
"""

DARK_THEME = """
QWidget { background-color: #2b2b2b; color: #ddd; font-family: Segoe UI; font-size: 10pt; }
QPushButton { background-color: #3b82f6; color: white; padding: 6px; border-radius: 4px; }
QPushButton:hover { background-color: #2563eb; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: #1e1e1e; color: white; border: 1px solid #444; border-radius: 4px; padding: 4px; }
QTabBar::tab { padding: 6px 12px; }
QLabel { font-weight: 500; }
"""

def kill_processes_with_cmdline_reference_to_file(file_path):
    import psutil
    import os

    abs_path = os.path.abspath(file_path)
    abs_path_lower = abs_path.lower()

    killed = set()

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = ' '.join(proc.info['cmdline']).lower()
            if abs_path_lower in cmd:
                print(f"[CMDLINE] Завершаем {proc.name()} (PID {proc.pid}) по ссылке в аргументах запуска")
                proc.kill()
                killed.add(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            print(f"[CMDLINE] Ошибка анализа процесса {proc.pid}: {e}")

    if not killed:
        print(f"[CMDLINE] Не найдено процессов с файлом в аргументах запуска.")

def kill_file_users_with_handle(file_path):
    import subprocess
    import re
    import psutil
    import os

    abs_path = os.path.abspath(file_path)

    try:
        result = subprocess.run(
            ["handle.exe", abs_path],
            capture_output=True, text=True
        )
        output = result.stdout.strip()

        if not output or "No matching handles found." in output:
            print(f"[HANDLE] Файл не используется: {abs_path}")
            return

        print(f"[HANDLE] Результат:\n{output}\n")

        pids = set(map(int, re.findall(r'pid: (\d+)', output)))

        for pid in pids:
            try:
                proc = psutil.Process(pid)
                print(f"[HANDLE] Завершаем процесс: {proc.name()} (PID {pid})")
                proc.kill()
            except Exception as e:
                print(f"[HANDLE] Не удалось завершить PID {pid}: {e}")

    except Exception as e:
        print(f"[HANDLE] Ошибка при вызове handle.exe: {e}")

class USBFileGuard(threading.Thread):
    def __init__(self, filename: str, on_violation):
        super().__init__(daemon=True)
        self.filename = os.path.basename(filename)
        self.on_violation = on_violation
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
            for drive in drives:
                try:
                    dtype = win32file.GetDriveType(drive)
                    if dtype == win32file.DRIVE_REMOVABLE:
                        for root, dirs, files in os.walk(drive):
                            if self.filename in files:
                                full_path = os.path.join(root, self.filename)
                                try:
                                    os.remove(full_path)
                                except:
                                    pass
                                self.on_violation(f"❌ Обнаружена копия на флешке: {full_path}")
                                return
                except:
                    continue
            time.sleep(3)

class TimerProcess(Process):
    def __init__(self, delay, paths):
        super().__init__()
        self.delay = delay
        self.paths = paths

    def run(self):
        time.sleep(self.delay)
        for path in self.paths:
            try:
                if path and os.path.exists(path):
                    from visual import secure_delete_file
                    secure_delete_file(path)
            except Exception:
                pass

def get_file_drive(path):
    return os.path.splitdrive(os.path.abspath(path))[0]

def secure_delete_file(path):
    try:
        kill_file_users_with_handle(path)
        kill_processes_with_cmdline_reference_to_file(path)

        if os.path.exists(path):
            with open(path, 'r+b') as f:
                length = os.path.getsize(path)
                f.write(b'\x00' * length)
                f.flush()

            os.remove(path)
            print(f"[Удаление] Файл удалён: {path}")
        else:
            print(f"[Удаление] Файл уже не существует: {path}")

    except Exception as e:
        print(f"[Удаление] Ошибка: {e}")

def calculate_file_hash(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

class FileGuard:
    def __init__(self, file_path, allow_drive, original_hash, on_violation):
        self.file_path = file_path
        self.allow_drive = allow_drive
        self.original_hash = original_hash
        self.on_violation = on_violation
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self.monitor, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop.set()

    def monitor(self):
        while not self._stop.is_set():
            try:
                if not os.path.exists(self.file_path):
                    return

                current_drive = get_file_drive(self.file_path)
                current_hash = calculate_file_hash(self.file_path)

                if self.allow_drive and current_drive != self.allow_drive:
                    os.remove(self.file_path)
                    self.on_violation("❌ Файл перемещён на другой носитель.")
                    return

                if self.original_hash and current_hash != self.original_hash:
                    os.remove(self.file_path)
                    self.on_violation("❌ Файл был изменён.")
                    return

            except Exception:
                self.on_violation("❌ Ошибка мониторинга файла.")
                return

            time.sleep(2)

class DropFrame(QFrame):
    def __init__(self, label, callback):
        super().__init__()
        self.label = QLabel(label)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout = QVBoxLayout(self)
        layout.addWidget(self.label)
        self.setAcceptDrops(True)
        self.callback = callback
        self.setStyleSheet("border: 2px dashed #666; border-radius: 6px; min-height: 100px")

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.callback(path)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryptor")
        self.setMinimumSize(600, 400)
        self.crypto = CryptoModule()
        self.clipboard = None
        self.theme = "Светлая"
        self.encryption_method = "AES-256-CBC"
        self.timer_seconds = 60
        self.copy_protection = True
        self.use_ip_mac = False
        self.max_opens = 5
        self.decrypted_file_path = None
        self.encrypted_file_path = None
        self.attachment_path = None  # Для email-вложения
        self.load_config()
        self.apply_theme()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()

        self.tabs.addTab(self.encryption_tab(), "🔒 Шифрование")
        self.tabs.addTab(self.decryption_tab(), "🔓 Расшифровка")
        self.tabs.addTab(self.email_tab(), "📧 Почта")  # Новый таб
        self.tabs.addTab(self.program_settings_tab(), "⚙ Настройки")

        self.meta_info_label = QLabel("Ожидание выбора файла...")
        self.meta_info_label.setWordWrap(True)
        layout.addWidget(self.tabs)
        layout.addWidget(self.meta_info_label)

    def encryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.enc_file_drop = DropFrame("Перетащите файл для шифрования", self.handle_enc_drop)
        self.enc_file_label = QLabel("Файл не выбран")
        self.enc_button = QPushButton("🔒 Зашифровать")
        self.enc_button.clicked.connect(self.encrypt_file)

        self.enc_method = QComboBox()
        self.enc_method.addItems(["AES-256-CBC"])
        self.enc_method.setCurrentText(self.encryption_method)
        self.enc_method.currentTextChanged.connect(self.update_encryption_method)

        self.timer_spin = QSpinBox()
        self.timer_spin.setRange(0, 3600)
        self.timer_spin.setValue(self.timer_seconds)
        self.timer_spin.valueChanged.connect(self.update_timer_value)

        self.copy_protect_check = QCheckBox("Защита от копирования")
        self.copy_protect_check.setChecked(self.copy_protection)
        self.copy_protect_check.stateChanged.connect(self.update_copy_protection)

        self.bind_check = QCheckBox("Привязка к IP/MAC")
        self.bind_check.setChecked(self.use_ip_mac)
        self.bind_check.stateChanged.connect(self.update_bind)

        self.max_opens_spin = QSpinBox()
        self.max_opens_spin.setRange(1, 100)
        self.max_opens_spin.setValue(self.max_opens)
        self.max_opens_spin.valueChanged.connect(self.update_max_opens)

        layout.addWidget(self.enc_file_drop)
        layout.addWidget(self.enc_file_label)
        layout.addWidget(QLabel("Метод шифрования:"))
        layout.addWidget(self.enc_method)
        layout.addWidget(QLabel("Таймер удаления (сек):"))
        layout.addWidget(self.timer_spin)
        layout.addWidget(self.copy_protect_check)
        layout.addWidget(self.bind_check)
        layout.addWidget(QLabel("Макс. открытий:"))
        layout.addWidget(self.max_opens_spin)
        layout.addWidget(self.enc_button)
        layout.addStretch()
        return tab

    def decryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.dec_file_drop = DropFrame("Перетащите файл для расшифровки", self.handle_dec_drop)
        self.dec_file_label = QLabel("Файл не выбран")
        self.dec_button = QPushButton("🔓 Расшифровать")
        self.dec_button.clicked.connect(self.decrypt_file)

        self.timer_ui = QLabel("⏳ Таймер не активен")
        self.timer_ui.setStyleSheet("font-weight: bold; color: #d32f2f")

        layout.addWidget(self.dec_file_drop)
        layout.addWidget(self.dec_file_label)
        layout.addWidget(self.timer_ui)
        layout.addWidget(self.dec_button)
        layout.addStretch()
        return tab

    def email_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Email получателя (например, user@example.com)")

        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("Тема письма")

        self.body_input = QTextEdit()
        self.body_input.setPlaceholderText("Текст письма")

        self.attachment_label = QLabel("Файл не выбран")
        self.attachment_button = QPushButton("📎 Выбрать файл")
        self.attachment_button.clicked.connect(self.select_attachment)

        self.send_button = QPushButton("📧 Отправить")
        self.send_button.clicked.connect(self.send_encrypted_email)

        self.smtp_config_button = QPushButton("⚙ Настроить SMTP")
        self.smtp_config_button.clicked.connect(self.open_smtp_config)

        layout.addWidget(QLabel("Получатель:"))
        layout.addWidget(self.recipient_input)
        layout.addWidget(QLabel("Тема:"))
        layout.addWidget(self.subject_input)
        layout.addWidget(QLabel("Сообщение:"))
        layout.addWidget(self.body_input)
        layout.addWidget(QLabel("Вложение:"))
        layout.addWidget(self.attachment_label)
        layout.addWidget(self.attachment_button)
        layout.addWidget(self.send_button)
        layout.addWidget(self.smtp_config_button)
        layout.addStretch()
        return tab

    def select_attachment(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выбрать файл", "", "Все файлы (*)")
        if file_path:
            self.attachment_label.setText(os.path.basename(file_path))
            self.attachment_path = file_path
        else:
            self.attachment_label.setText("Файл не выбран")
            self.attachment_path = None

    def open_smtp_config(self):
        dialog = SMTPConfigDialog(self)
        if dialog.exec():
            smtp_config = dialog.get_values()
            self.save_smtp_config(smtp_config)
            self.meta_info_label.setText("✅ SMTP настройки сохранены.")

    def send_encrypted_email(self):
        if not hasattr(self, 'attachment_path') or not self.attachment_path:
            self.meta_info_label.setText("❌ Выберите файл для отправки.")
            return

        recipient = self.recipient_input.text()
        subject = self.subject_input.text()
        body = self.body_input.toPlainText()

        if not recipient or not subject:
            self.meta_info_label.setText("❌ Заполните получателя и тему.")
            return

        smtp_config = self.load_smtp_config()
        if not all([smtp_config.get(k) for k in ['server', 'port', 'username', 'password']]):
            self.meta_info_label.setText("❌ Настройте SMTP в настройках.")
            return

        # Запрос пароля для шифрования
        password, ok = QInputDialog.getText(self, "Пароль", "Введите пароль для шифрования:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            self.meta_info_label.setText("❌ Пароль не введён.")
            return

        # Шифрование файла
        try:
            encrypted_path = self.crypto.encrypt_file(
                self.attachment_path,
                password=password,
                timer_seconds=self.timer_seconds,
                copy_protection=self.copy_protection,
                bind_to_ip_mac=self.use_ip_mac,
                max_opens=self.max_opens
            )
        except Exception as e:
            self.meta_info_label.setText(f"❌ Ошибка шифрования: {str(e)}")
            log_event("Ошибка шифрования", self.attachment_path, str(e))
            return

        # Отправка email
        msg = MIMEMultipart()
        msg['From'] = smtp_config['username']
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with open(encrypted_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(encrypted_path)}")
            msg.attach(part)

        try:
            server = smtplib.SMTP(smtp_config['server'], int(smtp_config['port']))
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            server.sendmail(smtp_config['username'], recipient, msg.as_string())
            server.quit()
            self.meta_info_label.setText("✅ Email отправлен безопасно.")
            log_event("Email отправлен", encrypted_path, f"Получатель: {recipient}")
        except Exception as e:
            self.meta_info_label.setText(f"❌ Ошибка отправки: {str(e)}")
            log_event("Ошибка email", encrypted_path, str(e))
        finally:
            if os.path.exists(encrypted_path):
                secure_delete_file(encrypted_path)

    def save_smtp_config(self, smtp_config):
        cfg = self.load_config() if os.path.exists(CONFIG_PATH) else {}
        cfg['smtp'] = smtp_config
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

    def load_smtp_config(self):
        cfg = self.load_config() if os.path.exists(CONFIG_PATH) else {}
        return cfg.get('smtp', {})

    def program_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        theme_box = QComboBox()
        theme_box.addItems(["Светлая", "Тёмная"])
        theme_box.setCurrentText(self.theme)
        theme_box.currentTextChanged.connect(self.change_theme)

        autorun_btn = QPushButton("🔁 В автозагрузку")
        autorun_btn.clicked.connect(self.set_autorun)

        admin_btn = QPushButton("🛡 Запуск от администратора")
        admin_btn.clicked.connect(self.run_as_admin)

        firewall_btn = QPushButton("🧱 В исключения брандмауэра")
        firewall_btn.clicked.connect(self.add_to_firewall)

        log_view_btn = QPushButton("📜 Журнал")
        log_view_btn.clicked.connect(self.open_log_viewer)

        license_btn = QPushButton("🧾 Лицензия")
        license_btn.clicked.connect(self.show_license)

        update_btn = QPushButton("🌍 Проверить обновления")
        update_btn.clicked.connect(self.check_updates)

        layout.addWidget(license_btn)
        layout.addWidget(update_btn)
        layout.addWidget(QLabel("Тема интерфейса:"))
        layout.addWidget(theme_box)
        layout.addWidget(autorun_btn)
        layout.addWidget(admin_btn)
        layout.addWidget(firewall_btn)
        layout.addWidget(log_view_btn)
        layout.addStretch()
        return tab

    def add_to_firewall(self):
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Encryptor", "dir=in", "action=allow",
                f"program={sys.executable}", "enable=yes"
            ], check=True)
            QMessageBox.information(self, "Брандмауэр", "Добавлено в исключения")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def open_log_viewer(self):
        viewer = LogViewer()
        viewer.exec()

    def change_theme(self, theme):
        self.theme = theme
        self.apply_theme()
        self.save_config()
        self.repaint()

    def apply_theme(self):
        self.setStyleSheet(LIGHT_THEME if self.theme == "Светлая" else DARK_THEME)

    def set_autorun(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "EncryptorApp", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            QMessageBox.information(self, "OK", "Добавлено в автозагрузку")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def run_as_admin(self):
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    def save_config(self):
        cfg = {
            "theme": self.theme,
            "encryption_method": self.encryption_method,
            "timer": self.timer_seconds,
            "copy_protection": self.copy_protection,
            "bind": self.use_ip_mac,
            "max_opens": self.max_opens
        }
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

    def load_config(self):
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
                self.theme = cfg.get("theme", self.theme)
                self.encryption_method = cfg.get("encryption_method", self.encryption_method)
                self.timer_seconds = cfg.get("timer", self.timer_seconds)
                self.copy_protection = cfg.get("copy_protection", self.copy_protection)
                self.use_ip_mac = cfg.get("bind", self.use_ip_mac)
                self.max_opens = cfg.get("max_opens", self.max_opens)

    def handle_enc_drop(self, path):
        self.enc_file_label.setText(os.path.basename(path))
        self.encrypted_file_path = path

    def handle_dec_drop(self, path):
        self.dec_file_label.setText(os.path.basename(path))
        self.encrypted_file_path = path

    def update_encryption_method(self, method):
        self.encryption_method = method
        self.save_config()

    def update_timer_value(self, value):
        self.timer_seconds = value
        self.save_config()

    def update_copy_protection(self, state):
        self.copy_protection = state == Qt.CheckState.Checked.value
        self.save_config()

    def update_bind(self, state):
        self.use_ip_mac = state == Qt.CheckState.Checked.value
        if self.use_ip_mac:
            dialog = IPMACDialog(self)
            if dialog.exec():
                self.ip_address, self.mac_address = dialog.get_values()
        self.save_config()

    def update_max_opens(self, value):
        self.max_opens = value
        self.save_config()

    def encrypt_file(self):
        if not self.encrypted_file_path:
            self.meta_info_label.setText("❌ Выберите файл для шифрования")
            return

        password, ok = QInputDialog.getText(self, "Пароль", "Введите пароль для шифрования:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            self.meta_info_label.setText("❌ Пароль не введён")
            return

        try:
            self.encrypted_file_path = self.crypto.encrypt_file(
                self.encrypted_file_path,
                password=password,
                method=self.encryption_method,
                timer_seconds=self.timer_seconds,
                copy_protection=self.copy_protection,
                bind_to_ip_mac=self.use_ip_mac,
                device_id=get_device_id() if self.use_ip_mac else None,
                ip_address=get_ip_address() if self.use_ip_mac else None,
                max_opens=self.max_opens
            )
            self.meta_info_label.setText(f"✅ Файл зашифрован: {self.encrypted_file_path}")
            log_event("Шифрование", self.encrypted_file_path, "Успешно")
        except Exception as e:
            self.meta_info_label.setText(f"❌ Ошибка шифрования: {str(e)}")
            log_event("Ошибка шифрования", self.encrypted_file_path, str(e))

    def decrypt_file(self):
        if not self.encrypted_file_path:
            self.meta_info_label.setText("❌ Выберите файл для расшифровки")
            return

        password, ok = QInputDialog.getText(self, "Пароль", "Введите пароль для расшифровки:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            self.meta_info_label.setText("❌ Пароль не введён")
            return

        try:
            output_path = self.encrypted_file_path + ".dec"
            self.decrypted_file_path, meta = self.crypto.decrypt_file(self.encrypted_file_path, password, output_path)
            self.meta_info_label.setText(f"✅ Расшифрован: {self.decrypted_file_path}\nОсталось открытий: {meta['max_opens'] - meta['current_opens']}")
            log_event("Расшифровка", self.decrypted_file_path, "Успешно")

            if meta.get("timer_seconds", 0) > 0:
                self.start_timer(meta["timer_seconds"])

            if meta.get("copy_protection"):
                self.clipboard = ClipboardProtector(self, self.handle_clipboard_violation)

            if meta.get("restrict_modification") or meta.get("restrict_move"):
                file_hash = calculate_file_hash(self.decrypted_file_path) if meta.get("restrict_modification") else None
                allow_drive = get_file_drive(self.decrypted_file_path) if meta.get("restrict_move") else None
                self.file_guard = FileGuard(self.decrypted_file_path, allow_drive, file_hash, self.handle_violation)
                self.file_guard.start()

            if meta.get("copy_protection"):
                self.usb_guard = USBFileGuard(self.decrypted_file_path, self.handle_violation)
                self.usb_guard.start()

        except Exception as e:
            self.meta_info_label.setText(f"❌ Ошибка расшифровки: {str(e)}")
            log_event("Ошибка расшифровки", self.encrypted_file_path, str(e))

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

        if hasattr(self, 'delete_timer_process') and self.delete_timer_process.is_alive():
            self.delete_timer_process.terminate()

        self.meta_info_label.setText(f"❌ {message}\nФайлы удалены.")
        self.timer_ui.setText("")
        self.dec_file_label.setText("Файл не выбран")
        self.tabs.setCurrentIndex(0)

        self.decrypted_file_path = None
        self.encrypted_file_path = None

    def delayed_destroy(self, delay):
        time.sleep(delay)
        self.destroy_files()

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
                    os.remove(p)
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

        self.decrypted_file_path = None
        self.encrypted_file_path = None

class SMTPConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки SMTP")
        self.setFixedSize(350, 250)
        layout = QVBoxLayout(self)

        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("smtp.gmail.com")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("587")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("your_email@gmail.com")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.save_btn = QPushButton("Сохранить")
        self.save_btn.clicked.connect(self.accept)

        layout.addWidget(QLabel("SMTP сервер:"))
        layout.addWidget(self.server_input)
        layout.addWidget(QLabel("Порт:"))
        layout.addWidget(self.port_input)
        layout.addWidget(QLabel("Логин:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_btn)

    def get_values(self):
        return {
            'server': self.server_input.text(),
            'port': self.port_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text()
        }

class IPMACDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Привязка к IP/MAC")
        self.setFixedSize(350, 200)

        layout = QVBoxLayout(self)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Пример: 192.168.1.100")

        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("Пример: aa:bb:cc:dd:ee:ff")

        self.save_btn = QPushButton("Сохранить")
        self.save_btn.clicked.connect(self.accept)

        layout.addWidget(QLabel("Введите IP-адрес:"))
        layout.addWidget(self.ip_input)
        layout.addWidget(QLabel("Введите MAC-адрес:"))
        layout.addWidget(self.mac_input)
        layout.addWidget(self.save_btn)

    def get_values(self):
        return self.ip_input.text(), self.mac_input.text()

def kill_processes_using_file(target_path):
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            files = proc.info['open_files']
            if files:
                for f in files:
                    if os.path.samefile(f.path, target_path):
                        proc.kill()
                        break
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

if __name__ == '__main__':
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())