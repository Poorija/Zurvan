import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFrame, QStackedWidget
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QPoint, QSize
from PyQt6.QtGui import QIcon, QPixmap, QFont

class AppLockDialog(QDialog):
    """
    A modal, full-screen dialog that locks the application until the correct
    password or PIN is entered. Features a two-stage unlock process.
    """
    def __init__(self, username, unlock_method, verification_callback, parent=None):
        super().__init__(parent)
        self.verification_callback = verification_callback
        self.unlock_method = unlock_method
        self.username = username

        # --- Window Properties ---
        self.setWindowTitle("Zurvan - Locked")
        self.setGeometry(parent.geometry())
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setModal(True)

        # --- Main Layout ---
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # --- Stacked Widget for different views ---
        self.stack = QStackedWidget(self)
        self.main_layout.addWidget(self.stack)

        # --- Create and add views ---
        self._create_initial_view()
        self._create_unlock_view()

        self._apply_stylesheet()
        self.stack.setCurrentIndex(0)

    def _create_initial_view(self):
        """Creates the initial view with the logo and username."""
        initial_widget = QWidget()
        layout = QVBoxLayout(initial_widget)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Full-screen logo
        logo_label = QLabel()
        pixmap = QPixmap(os.path.join("icons", "Zurvan.png"))
        logo_label.setPixmap(pixmap.scaled(QSize(256, 256), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)

        # Username button
        self.username_button = QPushButton(self.username)
        self.username_button.setObjectName("usernameButton")
        self.username_button.setMinimumHeight(40)
        self.username_button.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        layout.addWidget(self.username_button)

        self.stack.addWidget(initial_widget)

    def _create_unlock_view(self):
        """Creates the view with the input field for password/PIN."""
        self.central_frame = QFrame(self)
        self.central_frame.setObjectName("centralFrame")
        self.central_frame.setMaximumSize(350, 220)

        frame_layout = QVBoxLayout(self.central_frame)
        frame_layout.setSpacing(15)
        frame_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Title
        title_label = QLabel(f"Welcome, {self.username}")
        title_label.setObjectName("titleLabel")
        frame_layout.addWidget(title_label, 0, Qt.AlignmentFlag.AlignCenter)

        # Input field
        self.input_edit = QLineEdit(self)
        self.input_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_edit.setPlaceholderText(f"Enter Your {self.unlock_method.title()}")
        self.input_edit.returnPressed.connect(self._attempt_unlock)
        frame_layout.addWidget(self.input_edit)

        # Button layout
        button_layout = QHBoxLayout()
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("cancelButton")
        self.cancel_button.clicked.connect(lambda: self.stack.setCurrentIndex(0))

        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.clicked.connect(self._attempt_unlock)

        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.unlock_button)
        frame_layout.addLayout(button_layout)

        self.stack.addWidget(self.central_frame)

    def _apply_stylesheet(self):
        """Applies a dark, blurred background style."""
        self.setStyleSheet("""
            AppLockDialog {
                background-color: rgba(10, 10, 10, 0.92);
            }
            #usernameButton {
                font-size: 24px;
                font-weight: bold;
                color: #ffffff;
                background-color: transparent;
                border: none;
                padding: 10px;
            }
            #usernameButton:hover {
                color: #4a90e2;
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
                margin-bottom: 10px;
            }
            QLineEdit {
                padding: 10px;
                border-radius: 4px;
                border: 1px solid #555;
                background-color: #353b48;
                color: #f1f1f1;
                font-size: 14px;
            }
            QPushButton {
                padding: 10px;
                border-radius: 4px;
                background-color: #4a90e2;
                color: white;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #5fa8ff;
            }
            #cancelButton {
                background-color: #555;
            }
            #cancelButton:hover {
                background-color: #666;
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
        # The frame is inside the stack, which is centered. We need to get its position relative to the dialog.
        center_pos = self.rect().center() - self.central_frame.rect().center()

        anim.setDuration(400)
        anim.setLoopCount(1)
        anim.setEasingCurve(QEasingCurve.Type.Linear)
        anim.setKeyValueAt(0.0, center_pos)
        anim.setKeyValueAt(0.1, center_pos + QPoint(10, 0))
        anim.setKeyValueAt(0.2, center_pos)
        anim.setKeyValueAt(0.3, center_pos + QPoint(-10, 0))
        anim.setKeyValueAt(0.4, center_pos)
        anim.setKeyValueAt(0.5, center_pos + QPoint(10, 0))
        anim.setKeyValueAt(0.6, center_pos)
        anim.setKeyValueAt(0.7, center_pos + QPoint(-10, 0))
        anim.setKeyValueAt(0.8, center_pos)
        anim.setKeyValueAt(0.9, center_pos + QPoint(10, 0))
        anim.setKeyValueAt(1.0, center_pos)
        anim.start()
