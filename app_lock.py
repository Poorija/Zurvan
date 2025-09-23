import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QFrame
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QPoint
from PyQt6.QtGui import QIcon

class AppLockDialog(QDialog):
    """
    A modal, full-screen dialog that locks the application until the correct
    password or PIN is entered.
    """
    def __init__(self, unlock_method, verification_callback, parent=None):
        super().__init__(parent)
        self.verification_callback = verification_callback
        self.unlock_method = unlock_method

        # --- Window Properties ---
        self.setWindowTitle("Zurvan - Locked")
        # Cover the parent window's area
        self.setGeometry(parent.geometry())
        # Stay on top, be modal, and have no frame
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setModal(True)

        # --- UI Elements ---
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        # Use a central frame for styling and content
        self.central_frame = QFrame(self)
        self.central_frame.setObjectName("centralFrame")
        self.central_frame.setMaximumSize(350, 200) # Set a max size for the content box

        frame_layout = QVBoxLayout(self.central_frame)
        frame_layout.setSpacing(15)
        frame_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Lock Icon and Title
        title_layout = QHBoxLayout()
        lock_icon = QLabel()
        icon_path = os.path.join(os.path.dirname(__file__), 'icons', 'lock.svg')
        lock_icon.setPixmap(QIcon(icon_path).pixmap(32, 32))
        title_label = QLabel("Application Locked")
        title_label.setObjectName("titleLabel")
        title_layout.addWidget(lock_icon)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        frame_layout.addLayout(title_layout)

        # Input field
        self.input_edit = QLineEdit(self)
        self.input_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_edit.setPlaceholderText(f"Enter Your {self.unlock_method.title()}")
        self.input_edit.returnPressed.connect(self._attempt_unlock)
        frame_layout.addWidget(self.input_edit)

        # Unlock Button
        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.clicked.connect(self._attempt_unlock)
        frame_layout.addWidget(self.unlock_button)

        self.main_layout.addWidget(self.central_frame, 0, Qt.AlignmentFlag.AlignCenter)

        self._apply_stylesheet()

    def _apply_stylesheet(self):
        """Applies a dark, blurred background style."""
        self.setStyleSheet("""
            AppLockDialog {
                background-color: rgba(10, 10, 10, 0.85); /* Semi-transparent dark background */
            }
            #centralFrame {
                background-color: #2c313c;
                border-radius: 12px;
                padding: 20px;
                border: 1px solid #444;
            }
            #titleLabel {
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
            }
            QLineEdit {
                padding: 8px;
                border-radius: 4px;
                border: 1px solid #555;
                background-color: #353b48;
                color: #f1f1f1;
            }
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                background-color: #4a90e2;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5fa8ff;
            }
        """)

    def _attempt_unlock(self):
        """Handles the unlock attempt."""
        entered_value = self.input_edit.text()
        if not entered_value:
            self._shake_animation()
            return

        if self.verification_callback(entered_value):
            self.accept() # Close the dialog on success
        else:
            self.input_edit.clear()
            self._shake_animation()

    def _shake_animation(self):
        """Creates a shake animation for the central frame on failed attempts."""
        anim = QPropertyAnimation(self.central_frame, b"pos")
        pos = self.central_frame.pos()
        anim.setDuration(300)
        anim.setLoopCount(1)
        anim.setKeyValueAt(0.0, pos)
        anim.setKeyValueAt(0.1, pos + QPoint(10, 0))
        anim.setKeyValueAt(0.2, pos)
        anim.setKeyValueAt(0.3, pos + QPoint(-10, 0))
        anim.setKeyValueAt(0.4, pos)
        anim.setKeyValueAt(0.5, pos + QPoint(10, 0))
        anim.setKeyValueAt(0.6, pos)
        anim.setKeyValueAt(0.7, pos + QPoint(-10, 0))
        anim.setKeyValueAt(0.8, pos)
        anim.setKeyValueAt(0.9, pos + QPoint(10, 0))
        anim.setKeyValueAt(1.0, pos)
        anim.start()
