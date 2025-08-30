from PyQt6.QtWidgets import QWidget, QVBoxLayout, QGroupBox
from mail_widgets import MailComposeWidget, InboxWidget

class InternalMailClient(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        layout = QVBoxLayout(self)
        mail_group = QGroupBox("Отправка внутренней почты")
        mail_layout = QVBoxLayout(mail_group)
        self.compose_widget = MailComposeWidget(self.username)
        mail_layout.addWidget(self.compose_widget)
        layout.addWidget(mail_group)
        layout.addStretch()

    def set_attachment(self, file_path):
        self.compose_widget.set_attachment(file_path)

    @staticmethod
    def create_inbox_widget(username):
        return InboxWidget(username)