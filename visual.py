import os
import win32file
import sys
import json
import re
import multiprocessing
import threading
import time
import psutil
import subprocess
import ctypes
import winreg
import hashlib
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog,
    QLineEdit, QTabWidget, QTextEdit, QComboBox, QSpinBox, QCheckBox, QMessageBox, QFrame
)
from PyQt6.QtGui import QGuiApplication, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt
from crypto_module import CryptoModule
from device_checker import get_device_id, get_ip_address
from clipboard_protector import ClipboardProtector
from log_viewer import LogViewer
from PyQt6.QtCore import QTimer
from multiprocessing import Process


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
        kill_file_users_with_handle(path)  # Основной способ через дескрипторы
        kill_processes_with_cmdline_reference_to_file(path)  # Эвристика по cmdline

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

class TimerProcess(multiprocessing.Process):
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
            except: pass

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Шифровальщик")
        self.resize(960, 600)
        self.file_watcher = None
        self.crypto = CryptoModule()
        self.device_id = get_device_id()
        self.ip_address = get_ip_address()
        self.clipboard = QGuiApplication.clipboard()
        self.clip_protector = None
        self.theme = "Тёмная"

        self.encryption_method = "AES-256-CBC"
        self.timer_seconds = 0
        self.copy_protection = False
        self.use_ip_mac = False
        self.prevent_move = False
        self.prevent_edit = False
        self.max_opens = 5
        self.remaining = 0
        self.timer_countdown = None

        self.decrypted_file_path = None
        self.encrypted_file_path = None

        self.meta_info_label = QLabel()
        self.timer_ui = QLabel()

        self.load_config()

        self.tabs = QTabWidget()
        self.tabs.addTab(self.encrypt_tab(), "🔒 Шифрование")
        self.tabs.addTab(self.decrypt_tab(), "🔓 Расшифровка")
        self.tabs.addTab(self.help_tab(), "📘 Справка")
        self.tabs.addTab(self.program_settings_tab(), "⚙️ Настройки")

        layout = QVBoxLayout(self)
        layout.addWidget(self.tabs)
        self.apply_theme()


    def encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.enc_file_label = QLabel("Файл не выбран")
        drag = DropFrame("Перетащите файл сюда для шифровки", self.set_encrypt_path)
        drag.mousePressEvent = lambda e: self.select_file_encrypt()

        self.enc_password = QLineEdit()
        self.enc_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_password.setPlaceholderText("Пароль")

        btn = QPushButton("🔒 Зашифровать")
        btn.clicked.connect(self.encrypt_file)

        layout.addWidget(self.enc_file_label)
        layout.addWidget(drag)
        layout.addWidget(self.enc_password)
        layout.addLayout(self.encrypt_settings_layout())
        layout.addWidget(btn)
        layout.addStretch()
        return tab

    def encrypt_settings_layout(self):
        layout = QVBoxLayout()

        self.method_combo = QComboBox()
        self.method_combo.addItems(["AES-256-CBC", "ChaCha20", "Blowfish", "DES3"])
        self.method_combo.setCurrentText(self.encryption_method)
        self.method_combo.currentTextChanged.connect(lambda val: setattr(self, "encryption_method", val))

        self.timer_spin = QSpinBox()
        self.timer_spin.setRange(0, 3600)
        self.timer_spin.setValue(self.timer_seconds)
        self.timer_spin.valueChanged.connect(lambda v: setattr(self, "timer_seconds", v))

        self.copy_check = QCheckBox("Запретить копирование")
        self.copy_check.setChecked(self.copy_protection)
        self.copy_check.toggled.connect(lambda b: setattr(self, "copy_protection", b))

        self.bind_check = QCheckBox("Привязка к IP/MAC")
        self.bind_check.setChecked(self.use_ip_mac)
        self.bind_check.toggled.connect(lambda b: setattr(self, "use_ip_mac", b))

        self.prevent_move_check = QCheckBox("Запретить перенос на другие носители")
        self.prevent_move_check.setChecked(self.prevent_move)
        self.prevent_move_check.toggled.connect(lambda b: setattr(self, "prevent_move", b))

        self.prevent_edit_check = QCheckBox("Запретить редактирование файла")
        self.prevent_edit_check.setChecked(self.prevent_edit)
        self.prevent_edit_check.toggled.connect(lambda b: setattr(self, "prevent_edit", b))

        self.opens_spin = QSpinBox()
        self.opens_spin.setRange(1, 100)
        self.opens_spin.setValue(self.max_opens)
        self.opens_spin.valueChanged.connect(lambda v: setattr(self, "max_opens", v))

        layout.addWidget(QLabel("Метод шифрования:"))
        layout.addWidget(self.method_combo)
        layout.addWidget(QLabel("Таймер удаления (сек):"))
        layout.addWidget(self.timer_spin)
        layout.addWidget(QLabel("Максимум открытий:"))
        layout.addWidget(self.opens_spin)
        layout.addWidget(self.copy_check)
        layout.addWidget(self.bind_check)
        layout.addWidget(self.prevent_move_check)
        layout.addWidget(self.prevent_edit_check)
        return layout

    def help_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        text = QTextEdit("📘 Зашифруйте файл, передайте его. Все параметры сохраняются.")
        text.setReadOnly(True)
        layout.addWidget(text)
        return tab

    def decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.dec_file_label = QLabel("Файл не выбран")
        drag = DropFrame("Перетащите файл для расшифровки", self.set_decrypt_path)
        drag.mousePressEvent = lambda e: self.select_file_decrypt()

        self.dec_password = QLineEdit()
        self.dec_password.setPlaceholderText("Пароль")
        self.dec_password.setEchoMode(QLineEdit.EchoMode.Password)

        btn = QPushButton("🔓 Расшифровать")
        btn.clicked.connect(self.decrypt_file)

        layout.addWidget(self.dec_file_label)
        layout.addWidget(drag)
        layout.addWidget(self.dec_password)
        layout.addWidget(btn)
        layout.addWidget(self.meta_info_label)
        layout.addWidget(self.timer_ui)
        return tab

    def set_encrypt_path(self, path): self.enc_file_label.setText(path)
    def select_file_encrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Файл")
        if file_path: self.set_encrypt_path(file_path)

    def set_decrypt_path(self, path): self.dec_file_label.setText(path)
    def select_file_decrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Файл")
        if file_path: self.set_decrypt_path(file_path)

    def encrypt_file(self):
        path = self.enc_file_label.text()
        pwd = self.enc_password.text()
        if os.path.exists(path):
            out = self.crypto.encrypt_file(
                path, pwd, method=self.encryption_method,
                timer_seconds=self.timer_seconds, copy_protection=self.copy_protection,
                bind_to_ip_mac=self.use_ip_mac, device_id=self.device_id,
                ip_address=self.ip_address, max_opens=self.max_opens,
                restrict_modification=self.prevent_edit,
                restrict_move=self.prevent_move
            )
            QMessageBox.information(self, "Готово", f"Зашифровано: {out}")

    def decrypt_file(self):
        path = self.dec_file_label.text()
        pwd = self.dec_password.text()
        if not os.path.exists(path): return

        # ❌ Запрет расшифровки с USB-устройств
        drive = get_file_drive(path)
        try:
            import win32file
            drive_type = win32file.GetDriveType(drive + "\\")
            if drive_type == win32file.DRIVE_REMOVABLE:
                self.meta_info_label.setText("❌ Нельзя расшифровывать файл с USB-носителя.")
                self.tabs.setCurrentIndex(0)
                return
        except:
            pass

        try:
            save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как")
            if not save_path: return

            # ❌ Запрет сохранения на USB
            save_drive = get_file_drive(save_path)
            try:
                import win32file
                save_type = win32file.GetDriveType(save_drive + "\\")
                if save_type == win32file.DRIVE_REMOVABLE:
                    self.meta_info_label.setText("❌ Сохранение на флешку запрещено.")
                    self.tabs.setCurrentIndex(0)
                    return
            except:
                pass

            if os.path.exists(self.decrypted_file_path or ''):
                os.remove(self.decrypted_file_path)

            dec, meta = self.crypto.decrypt_file(path, pwd, output_path=save_path)
            self.decrypted_file_path = save_path
            self.encrypted_file_path = path

            # Проверка IP/MAC
            if meta.get("bind") and (
                    meta.get("device_id") != self.device_id or meta.get("ip_address") != self.ip_address):
                self.meta_info_label.setText("❌ Устройство не совпадает с заданным при шифровке.")
                self.destroy_files()
                return

            # Проверка лимита открытий
            if meta.get("max_opens") and meta["current_opens"] >= meta["max_opens"]:
                os.remove(path)
                self.meta_info_label.setText("❌ Лимит открытий исчерпан. Файл удалён.")
                self.destroy_files()
                return

            # Включение защиты от копирования
            if meta.get("copy_protection"):
                self.clip_protector = ClipboardProtector(self, self.handle_clipboard_violation)

            info = []
            if meta.get("max_opens"):
                info.append(f"🔁 Осталось открытий: {meta['max_opens'] - meta['current_opens']}")
            if meta.get("timer"):
                info.append("⏱ Удаление по таймеру включено")
                self.start_dynamic_timer(meta["timer"])
            self.meta_info_label.setText("\n".join(info))

            # Защита от перемещения / редактирования
            guard_drive = get_file_drive(save_path) if meta.get("restrict_move") else None
            guard_hash = calculate_file_hash(save_path) if meta.get("restrict_modification") else None

            if guard_drive or guard_hash:
                self.file_guard = FileGuard(
                    file_path=save_path,
                    allow_drive=guard_drive,
                    original_hash=guard_hash,
                    on_violation=self.handle_violation
                )
                self.file_guard.start()

            # 🔒 Запуск мониторинга копий на флешках
            self.usb_guard = USBFileGuard(save_path, self.handle_violation)
            self.usb_guard.start()

            # Обновление счётчика открытий
            self.crypto.update_meta_field(path, 'current_opens', meta['current_opens'])

            # Успешно
            self.meta_info_label.setText(self.meta_info_label.text() + "\n✅ Файл успешно расшифрован.")
            self.dec_file_label.setText("Файл не выбран")

        except Exception:
            self.meta_info_label.setText("❌ Ошибка при расшифровке.")
            self.destroy_files()

    def start_dynamic_timer(self, seconds):
        self.remaining = seconds
        self.timer_ui.setText(f"⏳ До удаления: {self.remaining} сек")

        # GUI таймер на экране
        self.timer_countdown = QTimer(self)
        self.timer_countdown.timeout.connect(self.update_timer)
        self.timer_countdown.start(1000)

        # Процесс-фоновый удалитель
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