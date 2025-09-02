import os
import sys
import json
import ctypes
import winreg
import urllib.request
import multiprocessing
import subprocess
from functools import partial
from dataclasses import dataclass
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog,
    QLineEdit, QTabWidget, QComboBox, QSpinBox, QCheckBox, QMessageBox, QGroupBox,
    QGridLayout, QDialog, QProgressBar, QHBoxLayout, QFrame, QListWidget, QListWidgetItem,
    QSystemTrayIcon, QMenu, QStyle, QSpacerItem, QSizePolicy, QToolButton
)
from PyQt6.QtCore import (
    QTimer, Qt, QEasingCurve, QPropertyAnimation, QParallelAnimationGroup, QPoint, QRect, pyqtSignal, QObject
)
from PyQt6.QtGui import QIcon, QKeySequence, QShortcut, QFont, QPixmap, QGuiApplication, QCursor, QPalette
from PyQt6.QtWidgets import QGraphicsOpacityEffect

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
QPushButton { background-color: #0288d1; color: white; padding: 12px 24px; border: none; border-radius: 10px; }
QPushButton:hover { background-color: #0277bd; }
QPushButton:disabled { background-color: #9bbfd3; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: #ffffff; color: #2e2e2e; border: 1px solid #b0bec5; border-radius: 10px; padding: 10px; }
QTabBar::tab { background: #e0e0e0; padding: 14px 28px; border-top-left-radius: 10px; border-top-right-radius: 10px; margin-right: 4px; }
QTabBar::tab:selected { background: #f5f6f5; font-weight: 600; }
QLabel { font-weight: 500; color: #455a64; }
QGroupBox { border: 1px solid #b0bec5; border-radius: 12px; padding: 16px; margin-top: 14px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 10px; }
QProgressBar { border: 1px solid #b0bec5; border-radius: 10px; text-align: center; }
QProgressBar::chunk { background-color: #0288d1; border-radius: 10px; }
QToolButton { border: none; padding: 6px 10px; border-radius: 8px; }
QToolButton:hover { background: #e7f2f9; }
"""

DARK_THEME = """
QWidget { background-color: #263238; color: #eceff1; font-family: Roboto; font-size: 13pt; }
QPushButton { background-color: #0288d1; color: white; padding: 12px 24px; border: none; border-radius: 10px; }
QPushButton:hover { background-color: #039be5; }
QPushButton:disabled { background-color: #466678; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: #37474f; color: #eceff1; border: 1px solid #546e7a; border-radius: 10px; padding: 10px; }
QTabBar::tab { background: #37474f; padding: 14px 28px; border-top-left-radius: 10px; border-top-right-radius: 10px; margin-right: 4px; }
QTabBar::tab:selected { background: #263238; font-weight: 600; }
QLabel { font-weight: 500; color: #b0bec5; }
QGroupBox { border: 1px solid #546e7a; border-radius: 12px; padding: 16px; margin-top: 14px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 10px; }
QProgressBar { border: 1px solid #546e7a; border-radius: 10px; text-align: center; }
QProgressBar::chunk { background-color: #0288d1; border-radius: 10px; }
QToolButton { border: none; padding: 6px 10px; border-radius: 8px; color: #e0f2f1; }
QToolButton:hover { background: #31444b; }
"""

# ---------- ВСПОМОГАТЕЛЬНЫЕ UI-КОМПОНЕНТЫ ----------

class Toast(QWidget):
    """Неблокирующие тост-уведомления с автозакрытием и анимацией."""
    def __init__(self, parent: QWidget, text: str, duration_ms: int = 2500):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.ToolTip)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        box = QVBoxLayout(self)
        box.setContentsMargins(16, 12, 16, 12)
        frame = QFrame()
        frame.setObjectName("toast-frame")
        frame.setStyleSheet("""
            #toast-frame {
                background: rgba(33,33,33,200);
                color: #fff; border-radius: 12px;
            }
            QLabel { color: #fff; font-weight: 500; }
        """)
        v = QVBoxLayout(frame)
        v.setContentsMargins(16, 12, 16, 12)
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        v.addWidget(lbl)
        box.addWidget(frame)

        self.opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity)
        self.fade_in = QPropertyAnimation(self.opacity, b"opacity", self)
        self.fade_in.setDuration(200)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.fade_out = QPropertyAnimation(self.opacity, b"opacity", self)
        self.fade_out.setDuration(250)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
        self.fade_out.finished.connect(self.close)

        QTimer.singleShot(15, self.fade_in.start)
        QTimer.singleShot(duration_ms, self.fade_out.start)

    def showEvent(self, e):
        # позиционирование: правый-нижний угол родителя
        if self.parent():
            pw = self.parent().width()
            ph = self.parent().height()
            self.adjustSize()
            self.move(pw - self.width() - 24, ph - self.height() - 24)
        super().showEvent(e)

class AnimatedTabWidget(QTabWidget):
    """Плавные переходы между вкладками (fade + slide)."""
    def __init__(self, *args, enable_animations=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.enable_animations = enable_animations
        self._last_index = -1
        self.currentChanged.connect(self._animate_change)
        self.setMovable(True)    # перетаскивание вкладок
        self.setDocumentMode(True)

    def _animate_change(self, idx: int):
        if not self.enable_animations:
            self._last_index = idx
            return

        if self._last_index == -1:
            self._last_index = idx
            return

        old_w = self.widget(self._last_index)
        new_w = self.widget(idx)
        if not old_w or not new_w or old_w == new_w:
            self._last_index = idx
            return

        # Эффект плавной смены прозрачности
        old_eff = QGraphicsOpacityEffect(old_w)
        new_eff = QGraphicsOpacityEffect(new_w)
        old_w.setGraphicsEffect(old_eff)
        new_w.setGraphicsEffect(new_eff)

        fade_out = QPropertyAnimation(old_eff, b"opacity")
        fade_out.setDuration(180)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QEasingCurve.Type.InOutCubic)

        fade_in = QPropertyAnimation(new_eff, b"opacity")
        fade_in.setDuration(250)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Слайд нового виджета
        start_pos = QPoint(self.rect().width() // 16, 0) if idx > self._last_index else QPoint(-self.rect().width() // 16, 0)
        slide = QPropertyAnimation(new_w, b"pos")
        slide.setDuration(280)
        slide.setStartValue(new_w.pos() + start_pos)
        slide.setEndValue(new_w.pos())
        slide.setEasingCurve(QEasingCurve.Type.OutCubic)

        grp = QParallelAnimationGroup(self)
        grp.addAnimation(fade_out)
        grp.addAnimation(fade_in)
        grp.addAnimation(slide)
        grp.finished.connect(lambda: (old_w.setGraphicsEffect(None), new_w.setGraphicsEffect(None)))
        grp.start(QParallelAnimationGroup.DeletionPolicy.DeleteWhenStopped)

        self._last_index = idx

class PasswordStrengthBar(QProgressBar):
    """Индикатор силы пароля с оценкой энтропии."""
    def __init__(self):
        super().__init__()
        self.setRange(0, 100)
        self.setValue(0)
        self.setFormat("Сила пароля: %p%")
        self.setToolTip("Оценка стойкости пароля (чем больше — тем лучше)")

    def update_strength(self, pwd: str):
        # Простая эвристика: длина + разнообразие наборов символов
        sets = [
            any(c.islower() for c in pwd),
            any(c.isupper() for c in pwd),
            any(c.isdigit() for c in pwd),
            any(not c.isalnum() for c in pwd)
        ]
        length_score = min(len(pwd) * 6, 60)  # до 60 баллов за длину
        variety_score = sum(sets) * 10        # до 40 баллов за разнообразие
        score = min(length_score + variety_score, 100)
        self.setValue(score)
        if score < 35:
            self.setStyleSheet("QProgressBar::chunk { background-color: #d32f2f; }")
        elif score < 70:
            self.setStyleSheet("QProgressBar::chunk { background-color: #ffa000; }")
        else:
            self.setStyleSheet("QProgressBar::chunk { background-color: #43a047; }")

class CommandPalette(QDialog):
    """Командная палитра (Ctrl+K) для быстрого доступа к действиям."""
    def __init__(self, parent, actions: dict[str, callable]):
        super().__init__(parent)
        self.setWindowTitle("Command Palette")
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        frame = QFrame()
        frame.setStyleSheet("""
            QFrame { background: palette(base); border: 1px solid palette(mid); border-radius: 12px; }
            QLineEdit { padding: 12px; border: none; border-bottom: 1px solid palette(mid); border-top-left-radius: 12px; border-top-right-radius: 12px;}
            QListWidget { border: none; padding: 6px; }
        """)
        v = QVBoxLayout(frame)
        v.setContentsMargins(0, 0, 0, 0)

        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Найти команду…")
        self.list = QListWidget()
        self.actions = actions
        for name in actions.keys():
            QListWidgetItem(name, self.list)

        self.edit.textChanged.connect(self._filter)
        self.list.itemActivated.connect(self._run)

        v.addWidget(self.edit)
        v.addWidget(self.list)
        root.addWidget(frame)

        self.resize(520, 420)

    def showEvent(self, e):
        # центр по родительскому окну
        if self.parent():
            pw = self.parent().width()
            ph = self.parent().height()
            self.move(self.parent().x() + (pw - self.width()) // 2,
                      self.parent().y() + (ph - self.height()) // 3)
        self.edit.setFocus()
        super().showEvent(e)

    def _filter(self, text: str):
        text = text.lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(text not in item.text().lower())

    def _run(self, item: QListWidgetItem):
        action = self.actions.get(item.text())
        if action:
            self.accept()
            QTimer.singleShot(0, action)

# ---------- АВТОРИЗАЦИЯ ----------

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Авторизация")
        self.resize(420, 320)
        self.setStyleSheet(LIGHT_THEME)

        layout = QVBoxLayout()

        title = QLabel("🔐 Добро пожаловать в Encryptor")
        title.setStyleSheet("font-size: 18pt; font-weight: 700;")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Имя пользователя")
        self.username.setToolTip("Введите уникальное имя пользователя")

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Пароль")
        self.password.setToolTip("Введите пароль (минимум 8 символов)")

        self.pwd_strength = PasswordStrengthBar()
        self.password.textChanged.connect(self.pwd_strength.update_strength)

        row = QHBoxLayout()
        login_btn = QPushButton("Войти")
        login_btn.setToolTip("Войти в систему")
        login_btn.clicked.connect(self.login)

        register_btn = QPushButton("Регистрация")
        register_btn.setToolTip("Создать новый аккаунт")
        register_btn.clicked.connect(self.register)

        row.addWidget(login_btn)
        row.addWidget(register_btn)

        layout.addWidget(title)
        layout.addSpacing(6)
        layout.addWidget(QLabel("Имя пользователя:"))
        layout.addWidget(self.username)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password)
        layout.addWidget(self.pwd_strength)
        layout.addSpacing(10)
        layout.addLayout(row)
        layout.addStretch()

        self.setLayout(layout)

        # Enter — сразу войти
        QShortcut(QKeySequence(Qt.Key.Key_Return), self, activated=self.login)
        QShortcut(QKeySequence(Qt.Key.Key_Enter), self, activated=self.login)

    def _toast(self, text):
        t = Toast(self, text)
        t.show()

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
            self._toast("Пользователь зарегистрирован")
        except ValueError as e:
            log_event(f"Ошибка регистрации: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

# ---------- ОСНОВНОЕ ОКНО ----------

@dataclass
class AppSettings:
    theme: str = "Светлая"
    encryption_method: str = "AES-256-GCM"
    timer: int = 300
    copy_protection: bool = False
    bind: bool = False
    max_opens: int = 5
    animations: bool = True
    minimize_to_tray: bool = True
    play_sounds: bool = False  # хук на будущее

class MainWindow(QWidget):
    # сигнал для «живого» статуса в статус-строке (внизу)
    status_message = pyqtSignal(str, int)

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("🔒 Encryptor")
        self.resize(1000, 760)

        self.settings = AppSettings()
        self.decrypted_file_path = None
        self.encrypted_file_path = None
        self.clipboard = None
        self.ip_address = None
        self.mac_address = None

        self.load_config()
        self.apply_theme()
        self._build_tray()
        self.init_ui()
        self._connect_status()

        # Горячие клавиши
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self.open_command_palette)
        QShortcut(QKeySequence("Ctrl+1"), self, activated=lambda: self.tabs.setCurrentIndex(0))
        QShortcut(QKeySequence("Ctrl+2"), self, activated=lambda: self.tabs.setCurrentIndex(1))
        QShortcut(QKeySequence("Ctrl+3"), self, activated=lambda: self.tabs.setCurrentIndex(2))
        QShortcut(QKeySequence("Ctrl+4"), self, activated=lambda: self.tabs.setCurrentIndex(3))
        QShortcut(QKeySequence("Ctrl+5"), self, activated=lambda: self.tabs.setCurrentIndex(4))

    # ---------- Построение UI ----------

    def init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Верхняя панель быстрых действий
        header = QHBoxLayout()
        header.setSpacing(8)

        hello = QLabel(f"Привет, {self.username} 👋")
        hello.setStyleSheet("font-weight: 700; font-size: 16pt;")

        header.addWidget(hello)
        header.addItem(QSpacerItem(20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        theme_btn = QToolButton()
        theme_btn.setToolTip("Переключить тему")
        theme_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        theme_btn.clicked.connect(self.toggle_theme)

        palette_btn = QToolButton()
        palette_btn.setToolTip("Командная палитра (Ctrl+K)")
        palette_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogListView))
        palette_btn.clicked.connect(self.open_command_palette)

        help_btn = QToolButton()
        help_btn.setToolTip("Справка и горячие клавиши")
        help_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation))
        help_btn.clicked.connect(self.show_help)

        header.addWidget(palette_btn)
        header.addWidget(theme_btn)
        header.addWidget(help_btn)

        # Статус-строка (простая)
        self.status = QLabel("Готово")
        self.status.setStyleSheet("opacity: 0.8;")

        # Вкладки с анимацией
        self.tabs = AnimatedTabWidget(enable_animations=self.settings.animations)
        self.tabs.addTab(self.encryption_tab(), "🔐 Шифрование")
        self.tabs.addTab(self.decryption_tab(), "🔓 Расшифровка")
        self.tabs.addTab(self.mail_tab(), "📧 Внутренняя почта")
        self.tabs.addTab(self.inbox_tab(), "📥 Входящие")
        self.tabs.addTab(self.program_settings_tab(), "⚙ Настройки")

        root.addLayout(header)
        root.addWidget(self.tabs)
        root.addWidget(self.status)

    def _connect_status(self):
        self.status_message.connect(lambda text, ms: self._set_status(text, ms))

    def _set_status(self, text: str, ms: int = 2500):
        self.status.setText(text)
        # легкая «подсветка» через тост и авто-очистка
        Toast(self, text, duration_ms=min(ms, 4000)).show()
        if ms > 0:
            QTimer.singleShot(ms, lambda: self.status.setText("Готово"))

    # ---------- ВКЛАДКИ ----------

    def encryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Группа «Шифрование файла»
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

        # Индикатор силы пароля
        self.enc_pwd_strength = PasswordStrengthBar()
        self.enc_password.textChanged.connect(self.enc_pwd_strength.update_strength)

        self.enc_method = QComboBox()
        self.enc_method.addItems(["AES-256-GCM", "ChaCha20"])
        self.enc_method.setCurrentText(self.settings.encryption_method)
        self.enc_method.setToolTip("Выберите алгоритм шифрования")

        self.timer_spin = QSpinBox()
        self.timer_spin.setRange(0, 3600)
        self.timer_spin.setValue(self.settings.timer)
        self.timer_spin.setSuffix(" сек")
        self.timer_spin.setToolTip("Время до автоматического удаления файла")

        self.copy_protection_cb = QCheckBox("Защита от копирования")
        self.copy_protection_cb.setChecked(self.settings.copy_protection)
        self.copy_protection_cb.setToolTip("Запретить копирование содержимого файла")

        self.restrict_mod_cb = QCheckBox("Запретить изменение")
        self.restrict_mod_cb.setToolTip("Запретить изменение файла")

        self.restrict_move_cb = QCheckBox("Запретить перемещение")
        self.restrict_move_cb.setToolTip("Запретить перемещение файла на другой диск")

        self.bind_ip_mac_cb = QCheckBox("Привязка к IP/MAC")
        self.bind_ip_mac_cb.setChecked(self.settings.bind)
        self.bind_ip_mac_cb.setToolTip("Привязать файл к IP/MAC текущего устройства")
        self.bind_ip_mac_cb.stateChanged.connect(self.show_ip_mac_dialog)

        self.max_opens_spin = QSpinBox()
        self.max_opens_spin.setRange(1, 100)
        self.max_opens_spin.setValue(self.settings.max_opens)
        self.max_opens_spin.setToolTip("Максимальное количество открытий файла")

        # Кнопки действий + прогресс
        self.encrypt_btn = QPushButton("🔐 Зашифровать")
        self.encrypt_btn.setToolTip("Начать шифрование файла")
        self.encrypt_btn.clicked.connect(self.encrypt_file)

        self.enc_progress = QProgressBar()
        self.enc_progress.setVisible(False)
        self.enc_progress.setRange(0, 0)  # «бегущая» индикация

        # Компоновка
        r = 0
        enc_layout.addWidget(QLabel("Файл для шифрования:"), r, 0)
        enc_layout.addWidget(self.enc_file_label, r, 1); r += 1
        enc_layout.addWidget(self.enc_drop_frame, r, 0, 1, 2); r += 1
        enc_layout.addWidget(self.enc_select_btn, r, 0, 1, 2); r += 1
        enc_layout.addWidget(QLabel("Пароль:"), r, 0)
        enc_layout.addWidget(self.enc_password, r, 1); r += 1
        enc_layout.addWidget(self.enc_pwd_strength, r, 0, 1, 2); r += 1
        enc_layout.addWidget(QLabel("Метод шифрования:"), r, 0)
        enc_layout.addWidget(self.enc_method, r, 1); r += 1
        enc_layout.addWidget(QLabel("Таймер удаления:"), r, 0)
        enc_layout.addWidget(self.timer_spin, r, 1); r += 1
        enc_layout.addWidget(self.copy_protection_cb, r, 0, 1, 2); r += 1
        enc_layout.addWidget(self.restrict_mod_cb, r, 0, 1, 2); r += 1
        enc_layout.addWidget(self.restrict_move_cb, r, 0, 1, 2); r += 1
        enc_layout.addWidget(self.bind_ip_mac_cb, r, 0, 1, 2); r += 1
        enc_layout.addWidget(QLabel("Макс. количество открытий:"), r, 0)
        enc_layout.addWidget(self.max_opens_spin, r, 1); r += 1

        # Нижняя панель действий
        buttons_row = QHBoxLayout()
        buttons_row.addWidget(self.encrypt_btn)
        buttons_row.addWidget(self.enc_progress)
        buttons_row.addStretch()

        layout.addWidget(enc_group)
        layout.addLayout(buttons_row)
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

        # Индикатор силы (необязательно, но полезно)
        self.dec_pwd_strength = PasswordStrengthBar()
        self.dec_password.textChanged.connect(self.dec_pwd_strength.update_strength)

        self.decrypt_btn = QPushButton("🔓 Расшифровать")
        self.decrypt_btn.setToolTip("Начать расшифровку файла")
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        self.dec_progress = QProgressBar()
        self.dec_progress.setVisible(False)
        self.dec_progress.setRange(0, 0)

        self.meta_info_label = QLabel("")
        self.meta_info_label.setWordWrap(True)
        self.timer_ui = QLabel("")

        r = 0
        dec_layout.addWidget(QLabel("Файл для расшифровки:"), r, 0)
        dec_layout.addWidget(self.dec_file_label, r, 1); r += 1
        dec_layout.addWidget(self.dec_drop_frame, r, 0, 1, 2); r += 1
        dec_layout.addWidget(self.dec_select_btn, r, 0, 1, 2); r += 1
        dec_layout.addWidget(QLabel("Пароль:"), r, 0)
        dec_layout.addWidget(self.dec_password, r, 1); r += 1
        dec_layout.addWidget(self.dec_pwd_strength, r, 0, 1, 2); r += 1
        dec_layout.addWidget(self.decrypt_btn, r, 0, 1, 2); r += 1
        dec_layout.addWidget(self.dec_progress, r, 0, 1, 2); r += 1
        dec_layout.addWidget(self.meta_info_label, r, 0, 1, 2); r += 1
        dec_layout.addWidget(self.timer_ui, r, 0, 1, 2); r += 1

        layout.addWidget(dec_group)
        layout.addStretch()
        return tab

    def mail_tab(self):
        # Нативный виджет клиента — уже функциональный
        tab = InternalMailClient(self.username)
        tab.setToolTip("Отправляйте зашифрованные файлы по внутренней почте")
        return tab

    def inbox_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        inbox_group = QGroupBox("Входящие сообщения")
        inbox_layout = QVBoxLayout(inbox_group)

        self.inbox_text = InternalMailClient.create_inbox_widget(self.username)
        refresh_btn = QPushButton("🔄 Обновить")
        refresh_btn.setToolTip("Обновить список сообщений")
        refresh_btn.clicked.connect(lambda: (self.inbox_text.refresh(), self._set_status("Входящие обновлены", 1800)))

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
        theme_box.setCurrentText(self.settings.theme)
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

        animations_cb = QCheckBox("Плавные анимации интерфейса")
        animations_cb.setChecked(self.settings.animations)
        animations_cb.stateChanged.connect(lambda s: self._toggle_animations(bool(s)))

        tray_cb = QCheckBox("Сворачивать в трей")
        tray_cb.setChecked(self.settings.minimize_to_tray)
        tray_cb.stateChanged.connect(lambda s: setattr(self.settings, "minimize_to_tray", bool(s)))

        settings_layout.addWidget(QLabel("Тема интерфейса:"), 0, 0)
        settings_layout.addWidget(theme_box, 0, 1)
        settings_layout.addWidget(animations_cb, 1, 0, 1, 2)
        settings_layout.addWidget(tray_cb, 2, 0, 1, 2)
        settings_layout.addWidget(autorun_btn, 3, 0, 1, 2)
        settings_layout.addWidget(admin_btn, 4, 0, 1, 2)
        settings_layout.addWidget(firewall_btn, 5, 0, 1, 2)
        settings_layout.addWidget(log_view_btn, 6, 0, 1, 2)
        settings_layout.addWidget(license_btn, 7, 0, 1, 2)
        settings_layout.addWidget(update_btn, 8, 0, 1, 2)

        layout.addWidget(settings_group)
        layout.addStretch()
        return tab

    # ---------- Командная палитра ----------

    def open_command_palette(self):
        actions = {
            "Открыть: Шифрование": lambda: self.tabs.setCurrentIndex(0),
            "Открыть: Расшифровка": lambda: self.tabs.setCurrentIndex(1),
            "Открыть: Внутренняя почта": lambda: self.tabs.setCurrentIndex(2),
            "Открыть: Входящие": lambda: self.tabs.setCurrentIndex(3),
            "Открыть: Настройки": lambda: self.tabs.setCurrentIndex(4),
            "Переключить тему": self.toggle_theme,
            "Открыть лог": self.open_log_viewer,
            "Проверить обновления": self.check_updates,
            "Добавить в автозагрузку": self.set_autorun,
            "Запуск от администратора": self.run_as_admin,
        }
        dlg = CommandPalette(self, actions)
        dlg.exec()

    # ---------- Трей ----------

    def _build_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogYesButton))
        menu = QMenu()
        act_show = QAction("Показать", self, triggered=self.show_normal_from_tray)
        act_quit = QAction("Выход", self, triggered=self.close)
        menu.addAction(act_show)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.show_normal_from_tray() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def show_normal_from_tray(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def closeEvent(self, e):
        # сворачивание в трей вместо закрытия (если включено)
        if self.settings.minimize_to_tray and self.tray.isVisible():
            e.ignore()
            self.hide()
            self.tray.showMessage("Encryptor", "Приложение свернуто в трей")
        else:
            self.save_config()
            super().closeEvent(e)

    # ---------- Вспомогательные действия ----------

    def select_enc_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.enc_file_label.setText(os.path.basename(file_path))
            self.enc_drop_frame.label.setText(os.path.basename(file_path))
            self.enc_file_path = file_path
            self._pulse_label(self.enc_file_label)
            log_event(f"Выбран файл для шифрования: {file_path}")
            self.status_message.emit("Файл выбран для шифрования", 2000)

    def select_dec_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", filter="Encrypted files (*.enc)")
        if file_path:
            self.dec_file_label.setText(os.path.basename(file_path))
            self.dec_drop_frame.label.setText(os.path.basename(file_path))
            self.dec_file_path = file_path
            self._pulse_label(self.dec_file_label)
            log_event(f"Выбран файл для расшифровки: {file_path}")
            self.status_message.emit("Файл выбран для расшифровки", 2000)

    def set_enc_file(self, path):
        self.enc_file_label.setText(os.path.basename(path))
        self.enc_drop_frame.label.setText(os.path.basename(path))
        self.enc_file_path = path
        self._pulse_label(self.enc_file_label)
        log_event(f"Перетащен файл для шифрования: {path}")

    def set_dec_file(self, path):
        self.dec_file_label.setText(os.path.basename(path))
        self.dec_drop_frame.label.setText(os.path.basename(path))
        self.dec_file_path = path
        self._pulse_label(self.dec_file_label)
        log_event(f"Перетащен файл для расшифровки: {path}")

    def _pulse_label(self, label: QLabel):
        eff = QGraphicsOpacityEffect(label)
        label.setGraphicsEffect(eff)
        anim = QPropertyAnimation(eff, b"opacity", self)
        anim.setDuration(280)
        anim.setStartValue(0.2)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.finished.connect(lambda: label.setGraphicsEffect(None))
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def show_ip_mac_dialog(self):
        if self.bind_ip_mac_cb.isChecked():
            dialog = IPMACDialog(self)
            if dialog.exec():
                ip, mac = dialog.get_values()
                self.ip_address = ip
                self.mac_address = mac
                log_event(f"Установлены IP/MAC: {ip}/{mac}")
                self.status_message.emit("Привязка к IP/MAC включена", 2000)
            else:
                self.bind_ip_mac_cb.setChecked(False)
                log_event("Отменена привязка к IP/MAC")

    # ---------- Крипто-операции с улучшенным UX ----------

    def _lock_ui(self, encrypting: bool):
        if encrypting:
            self.encrypt_btn.setEnabled(False)
            self.enc_progress.setVisible(True)
        else:
            self.encrypt_btn.setEnabled(True)
            self.enc_progress.setVisible(False)

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
            self._lock_ui(True)
            QApplication.processEvents()

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

            self.status_message.emit("Файл зашифрован", 2500)
            Toast(self, "Файл зашифрован. Готов к отправке ✉").show()

            QMessageBox.information(self, "Успех", f"Файл зашифрован: {out_path}\nОтправьте его через вкладку 'Внутренняя почта'.")
            self.tabs.setCurrentIndex(2)
            # если клиент поддерживает set_attachment
            try:
                self.mail_tab().set_attachment(out_path)
            except Exception:
                pass

            # reset
            self.enc_file_label.setText("Файл не выбран")
            self.enc_drop_frame.label.setText("Перетащите файл сюда")
            self.enc_file_path = None

        except Exception as e:
            log_event(f"Ошибка шифрования: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))
        finally:
            self._lock_ui(False)

    def _lock_ui_dec(self, decrypting: bool):
        if decrypting:
            self.decrypt_btn.setEnabled(False)
            self.dec_progress.setVisible(True)
        else:
            self.decrypt_btn.setEnabled(True)
            self.dec_progress.setVisible(False)

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
            self._lock_ui_dec(True)
            QApplication.processEvents()

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
            self.status_message.emit("Файл расшифрован", 2500)

        except Exception as e:
            log_event(f"Ошибка расшифровки: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))
        finally:
            self._lock_ui_dec(False)

    # ---------- Таймер и реакции на нарушения ----------

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
        self.status_message.emit("Файлы удалены из-за нарушения", 3500)

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
        self.status_message.emit("Файлы удалены", 3000)

    def update_timer(self):
        self.remaining -= 1
        if self.remaining <= 0:
            self.timer_countdown.stop()
            self.timer_ui.setText("⏳ Файл будет удалён…")
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
        self.status_message.emit("Копирование запрещено: файлы удалены", 3500)

    # ---------- Системные/служебные действия ----------

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
        self.settings.theme = theme
        self.apply_theme()
        self.save_config()
        self.repaint()
        log_event(f"Изменена тема на: {theme}")
        self.status_message.emit(f"Тема: {theme}", 1500)

    def toggle_theme(self):
        self.change_theme("Тёмная" if self.settings.theme == "Светлая" else "Светлая")

    def _toggle_animations(self, enabled: bool):
        self.settings.animations = enabled
        # Пересоздавать вкладки не будем — у нас проверка флага в AnimatedTabWidget
        self.tabs.enable_animations = enabled
        self.status_message.emit("Анимации " + ("включены" if enabled else "выключены"), 1800)

    def apply_theme(self):
        self.setStyleSheet(LIGHT_THEME if self.settings.theme == "Светлая" else DARK_THEME)

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

    def show_help(self):
        text = (
            "<b>Горячие клавиши</b><br>"
            "• Ctrl+K — командная палитра<br>"
            "• Ctrl+1…Ctrl+5 — переключение вкладок<br>"
            "• Enter — вход в окне авторизации<br><br>"
            "<b>Советы</b><br>"
            "• Перетаскивайте файлы прямо на рамку-приёмник.<br>"
            "• В настройках можно отключить анимации и включить сворачивание в трей."
        )
        QMessageBox.information(self, "Справка", text)

    # ---------- Конфиг ----------

    def save_config(self):
        cfg = {
            "theme": self.settings.theme,
            "encryption_method": self.settings.encryption_method,
            "timer": self.settings.timer,
            "copy_protection": self.settings.copy_protection,
            "bind": self.settings.bind,
            "max_opens": self.settings.max_opens,
            "animations": self.settings.animations,
            "minimize_to_tray": self.settings.minimize_to_tray,
            "play_sounds": self.settings.play_sounds
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
                self.settings.theme = cfg.get("theme", self.settings.theme)
                self.settings.encryption_method = cfg.get("encryption_method", self.settings.encryption_method)
                self.settings.timer = cfg.get("timer", self.settings.timer)
                self.settings.copy_protection = cfg.get("copy_protection", self.settings.copy_protection)
                self.settings.bind = cfg.get("bind", self.settings.bind)
                self.settings.max_opens = cfg.get("max_opens", self.settings.max_opens)
                self.settings.animations = cfg.get("animations", self.settings.animations)
                self.settings.minimize_to_tray = cfg.get("minimize_to_tray", self.settings.minimize_to_tray)
                self.settings.play_sounds = cfg.get("play_sounds", self.settings.play_sounds)
                log_event("Конфигурация загружена")
            except Exception as e:
                log_event(f"Ошибка загрузки конфигурации: {str(e)}")

# ---------- Точка входа ----------

if __name__ == '__main__':
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    # Небольшой твик хинтов рендеринга шрифтов
    f = QFont("Roboto", 10)
    app.setFont(f)

    login_dialog = LoginDialog()
    if login_dialog.exec() == QDialog.DialogCode.Accepted:
        window = MainWindow(login_dialog.username_value)
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)
