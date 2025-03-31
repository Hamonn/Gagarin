from PyQt6.QtWidgets import QSystemTrayIcon, QMenu, QMessageBox
from PyQt6.QtGui import QIcon
from PyQt6.QtGui import QAction

class TrayManager:
    def __init__(self, parent_window):
        self.parent = parent_window
        self.tray_icon = QSystemTrayIcon()
        self.tray_icon.setIcon(QIcon("icon.png"))

        self.menu = QMenu()
        self.show_action = QAction("🔓 Показать")
        self.hide_action = QAction("🔒 Скрыть")
        self.exit_action = QAction("❌ Выйти")

        self.show_action.triggered.connect(self.show_window)
        self.hide_action.triggered.connect(self.hide_window)
        self.exit_action.triggered.connect(self.exit_app)

        self.menu.addAction(self.show_action)
        self.menu.addAction(self.hide_action)
        self.menu.addSeparator()
        self.menu.addAction(self.exit_action)

        self.tray_icon.setContextMenu(self.menu)
        self.tray_icon.activated.connect(self.icon_clicked)

    def show_tray(self):
        self.tray_icon.show()

    def show_window(self):
        self.parent.showNormal()
        self.parent.activateWindow()

    def hide_window(self):
        self.parent.hide()

    def exit_app(self):
        confirm = QMessageBox.question(
            self.parent, "Выход", "Вы действительно хотите выйти?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.tray_icon.hide()
            self.parent.close()

    def icon_clicked(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.parent.isHidden():
                self.show_window()
            else:
                self.hide_window()
