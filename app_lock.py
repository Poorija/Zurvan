import sys
import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QWidget, QApplication, QFrame, QComboBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QFont, QPixmap

class AppLockDialog(QDialog):
    """
    A modern, modal dialog that locks the application and requires user authentication to unlock.
    It supports unlocking via PIN/Password or OTP, with a switcher to toggle between them.
    """
    def __init__(self, verification_callback, parent=None):
        super().__init__(parent)
        self.verification_callback = verification_callback

        self.setWindowTitle("Zurvan - Locked")
        self.setWindowIcon(QIcon("icons/Zurvan-mono.png"))
        self.setModal(True)
        # Make the dialog frameless and cover the parent
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setMinimumSize(450, 550)

        # Main vertical layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(25)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Logo
        logo_label = QLabel()
        pixmap = QPixmap(os.path.join(os.path.dirname(__file__), "icons", "Zurvan.png"))
        logo_label.setPixmap(pixmap.scaled(180, 180, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(logo_label)

        # Title
        title_label = QLabel("Application Locked")
        title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        # Unlock Method Switcher
        switcher_layout = QHBoxLayout()
        switcher_layout.addWidget(QLabel("Unlock Method:"))
        self.unlock_method_combo = QComboBox()
        self.unlock_method_combo.addItems(["PIN / Password", "OTP"])
        switcher_layout.addWidget(self.unlock_method_combo)
        main_layout.addLayout(switcher_layout)

        # Input Fields
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password or PIN")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("One-Time Password")
        self.otp_input.setVisible(False) # Hidden by default

        main_layout.addWidget(self.username_input)
        main_layout.addWidget(self.password_input)
        main_layout.addWidget(self.otp_input)

        # Unlock Button
        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.setFixedHeight(45)
        main_layout.addWidget(self.unlock_button)
        main_layout.addStretch()

        # Connections
        self.unlock_button.clicked.connect(self.verify)
        self.unlock_method_combo.currentTextChanged.connect(self._update_unlock_mode)
        self.password_input.returnPressed.connect(self.verify)
        self.username_input.returnPressed.connect(self.verify)
        self.otp_input.returnPressed.connect(self.verify)

        # Styling
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                border: 2px solid #4a90e2;
                border-radius: 15px;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 14px;
            }
            QLineEdit, QComboBox {
                padding: 12px;
                border: 1px solid #444;
                border-radius: 8px;
                background-color: #3c3c3c;
                color: #e0e0e0;
                font-size: 15px;
            }
            QPushButton {
                background-color: #4a90e2;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #5aa1f2;
            }
            QPushButton:pressed {
                background-color: #3a80d2;
            }
        """)

    def _update_unlock_mode(self, mode):
        """Shows/hides input fields based on the selected unlock method."""
        if mode == "PIN / Password":
            self.password_input.setVisible(True)
            self.otp_input.setVisible(False)
            self.password_input.setFocus()
        elif mode == "OTP":
            self.password_input.setVisible(False)
            self.otp_input.setVisible(True)
            self.otp_input.setFocus()

    def verify(self):
        """Gathers credentials based on the selected mode and calls the verification callback."""
        username = self.username_input.text().strip()
        mode = self.unlock_method_combo.currentText()
        password = ""
        otp = ""

        if not username:
            QMessageBox.warning(self, "Input Required", "Username is required.")
            return

        if mode == "PIN / Password":
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "Input Required", "Password/PIN is required.")
                return
        elif mode == "OTP":
            otp = self.otp_input.text().strip()
            if not otp:
                QMessageBox.warning(self, "Input Required", "One-Time Password is required.")
                return

        # The callback now receives all possible fields, and the logic inside zurvan.py will handle it
        if self.verification_callback(username, password, otp):
            self.accept()
        else:
            QMessageBox.warning(self, "Authentication Failed", "Invalid credentials. Please try again.")
            # Clear the relevant field
            if mode == "PIN / Password":
                self.password_input.clear()
                self.password_input.setFocus()
            else:
                self.otp_input.clear()
                self.otp_input.setFocus()

    def closeEvent(self, event):
        """Prevents the user from closing the lock screen with Alt+F4."""
        event.ignore()