import os
import json
import base64
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QTextEdit, QPushButton, QHBoxLayout, QLabel, QFileDialog, QMessageBox, QTextBrowser, QDialog, QTextEdit
from PyQt6.QtCore import Qt, QUrl
from database import Database
from utils import log_event

class MailComposeWidget(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        layout = QVBoxLayout(self)

        self.to_user = QLineEdit()
        self.to_user.setPlaceholderText("Получатель (имя пользователя)")
        self.to_user.setToolTip("Введите имя зарегистрированного пользователя")

        self.subject = QLineEdit()
        self.subject.setPlaceholderText("Тема")
        self.subject.setToolTip("Введите тему сообщения")

        self.body = QTextEdit()
        self.body.setPlaceholderText("Текст сообщения")
        self.body.setToolTip("Введите текст сообщения")

        attach_layout = QHBoxLayout()
        self.attachment_label = QLabel("Нет вложения")
        self.attach_btn = QPushButton("📎 Прикрепить файл")
        self.attach_btn.setToolTip("Прикрепить зашифрованный файл (.enc)")
        self.attach_btn.clicked.connect(self.select_attachment)
        attach_layout.addWidget(self.attachment_label)
        attach_layout.addWidget(self.attach_btn)

        self.send_btn = QPushButton("📤 Отправить")
        self.send_btn.setToolTip("Отправить сообщение")
        self.send_btn.clicked.connect(self.send_message)

        layout.addWidget(QLabel("Кому:"))
        layout.addWidget(self.to_user)
        layout.addWidget(QLabel("Тема:"))
        layout.addWidget(self.subject)
        layout.addWidget(QLabel("Сообщение:"))
        layout.addWidget(self.body)
        layout.addLayout(attach_layout)
        layout.addWidget(self.send_btn)

    def select_attachment(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для вложения", filter="Encrypted files (*.enc)")
        if file_path:
            self.attachment_label.setText(os.path.basename(file_path))
            self.attachment_path = file_path
            log_event(f"Выбрано вложение: {file_path}")

    def set_attachment(self, file_path):
        if file_path and file_path.endswith('.enc'):
            self.attachment_label.setText(os.path.basename(file_path))
            self.attachment_path = file_path
            log_event(f"Установлено вложение: {file_path}")
        else:
            self.attachment_label.setText("Нет вложения")
            self.attachment_path = None
            log_event("Попытка установить неподходящее вложение")

    def send_message(self):
        to_user = self.to_user.text()
        subject = self.subject.text()
        body = self.body.toPlainText()
        attachment = getattr(self, 'attachment_path', None)

        if not to_user or not subject:
            QMessageBox.critical(self, "Ошибка", "Заполните получателя и тему")
            log_event("Попытка отправки сообщения без получателя или темы")
            return

        if attachment and not attachment.endswith('.enc'):
            QMessageBox.critical(self, "Ошибка", "Можно отправлять только зашифрованные файлы (.enc)")
            log_event("Попытка отправки не зашифрованного файла")
            return

        try:
            db = Database()
            db.send_message(self.username, to_user, subject, body, attachment)
            QMessageBox.information(self, "Успех", "Сообщение отправлено")
            log_event(f"Сообщение отправлено от {self.username} к {to_user}")
            self.to_user.clear()
            self.subject.clear()
            self.body.clear()
            self.attachment_label.setText("Нет вложения")
            self.attachment_path = None
        except ValueError as e:
            log_event(f"Ошибка отправки сообщения: {str(e)}")
            QMessageBox.critical(self, "Ошибка", str(e))

class AttachmentPreviewDialog(QDialog):
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Метаданные вложения")
        self.resize(400, 300)
        layout = QVBoxLayout(self)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)

        try:
            with open(file_path, 'rb') as f:
                data = base64.b64decode(f.read())
            separator_idx = data.find(b'|')
            meta_json = data[data.find(b'{"'):separator_idx]
            meta = json.loads(meta_json.decode())
            text_edit.setText(
                f"Метод шифрования: {meta['method']}\n"
                f"Таймер: {meta['timer']} сек\n"
                f"Защита от копирования: {'вкл' if meta['copy_protection'] else 'выкл'}\n"
                f"Привязка к IP/MAC: {'вкл' if meta['bind'] else 'выкл'}\n"
                f"Осталось открытий: {meta['max_opens'] - meta['current_opens']}\n"
                f"Запрет изменения: {'вкл' if meta['restrict_modification'] else 'выкл'}\n"
                f"Запрет перемещения: {'вкл' if meta['restrict_move'] else 'выкл'}"
            )
        except Exception as e:
            text_edit.setText(f"Ошибка чтения метаданных: {str(e)}")
            log_event(f"Ошибка чтения метаданных вложения {file_path}: {str(e)}")

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.close)
        layout.addWidget(text_edit)
        layout.addWidget(close_btn)

class InboxWidget(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        layout = QVBoxLayout(self)
        self.text_browser = QTextBrowser()
        self.text_browser.setOpenLinks(False)
        self.text_browser.anchorClicked.connect(self.handle_attachment_click)
        layout.addWidget(self.text_browser)
        self.refresh()

    def refresh(self):
        db = Database()
        messages = db.get_messages(self.username)
        html = "<style>a {color: #0288d1; text-decoration: none;}</style>"
        for msg in messages:
            msg_id, from_user, subject, body, attachment, timestamp = msg
            attachment_link = f'<a href="file://{attachment}">{os.path.basename(attachment)}</a> | <a href="preview://{msg_id}">Просмотр</a> | <a href="delete://{msg_id}">Удалить</a>' if attachment else 'Нет'
            html += (
                f"<b>От:</b> {from_user} | <b>Время:</b> {timestamp}<br>"
                f"<b>Тема:</b> {subject}<br>"
                f"<b>Сообщение:</b> {body.replace('\n', '<br>')}<br>"
                f"<b>Вложение:</b> {attachment_link}<br><hr>"
            )
        self.text_browser.setHtml(html)
        log_event(f"Обновлен список входящих для {self.username}")

    def handle_attachment_click(self, url):
        url_str = url.toString()
        if url_str.startswith("file://"):
            file_path = url_str[7:]
            if file_path and os.path.exists(file_path):
                save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить вложение", os.path.basename(file_path))
                if save_path:
                    shutil.copy(file_path, save_path)
                    log_event(f"Вложение сохранено: {save_path}")
                    QMessageBox.information(self, "Успех", f"Вложение сохранено в {save_path}")
        elif url_str.startswith("preview://"):
            msg_id = int(url_str[10:])
            db = Database()
            messages = db.get_messages(self.username)
            for msg in messages:
                if msg[0] == msg_id and msg[4]:
                    dialog = AttachmentPreviewDialog(msg[4], self)
                    dialog.exec()
                    break
        elif url_str.startswith("delete://"):
            msg_id = int(url_str[9:])
            reply = QMessageBox.question(self, "Подтверждение", "Удалить сообщение?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                db = Database()
                db.delete_message(msg_id)
                self.refresh()