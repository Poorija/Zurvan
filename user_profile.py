import os
import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QFileDialog,
    QLabel, QMessageBox, QGroupBox, QComboBox
)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt, QBuffer, QIODevice
import database

class UserProfileDialog(QDialog):
    def __init__(self, user, parent=None):
        super().__init__(parent)
        self.user = user
        self.setWindowTitle("User Profile")
        self.setMinimumSize(400, 500)

        self.main_layout = QVBoxLayout(self)
        self._create_widgets()
        self._populate_data()

    def _create_widgets(self):
        # --- Avatar Section ---
        avatar_box = QGroupBox("Avatar")
        avatar_layout = QVBoxLayout(avatar_box)
        self.avatar_label = QLabel("No avatar set.")
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar_label.setFixedSize(128, 128)
        self.avatar_label.setStyleSheet("border: 1px solid #888; border-radius: 64px;")
        change_avatar_btn = QPushButton("Change Avatar")
        change_avatar_btn.clicked.connect(self._change_avatar)
        avatar_layout.addWidget(self.avatar_label, 0, Qt.AlignmentFlag.AlignCenter)
        avatar_layout.addWidget(change_avatar_btn, 0, Qt.AlignmentFlag.AlignCenter)
        self.main_layout.addWidget(avatar_box)

        # --- Profile Details Section ---
        details_box = QGroupBox("Profile Details")
        details_layout = QFormLayout(details_box)
        self.username_label = QLabel()
        self.email_edit = QLineEdit()
        self.full_name_edit = QLineEdit()
        self.age_edit = QLineEdit()
        self.job_title_combo = QComboBox()
        self.job_title_combo.addItems(["Red Team", "Blue Team", "Purple Team", "IT Team", "Network Team", "Manager", "Other"])
        self.job_title_combo.setEditable(True)
        details_layout.addRow("Username:", self.username_label)
        details_layout.addRow("Email:", self.email_edit)
        details_layout.addRow("Full Name:", self.full_name_edit)
        details_layout.addRow("Age:", self.age_edit)
        details_layout.addRow("Job Title:", self.job_title_combo)
        self.main_layout.addWidget(details_box)

        # --- Password Change Section ---
        password_box = QGroupBox("Change Password")
        password_layout = QFormLayout(password_box)
        self.current_password_edit = QLineEdit()
        self.current_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addRow("Current Password:", self.current_password_edit)
        password_layout.addRow("New Password:", self.new_password_edit)
        password_layout.addRow("Confirm New Password:", self.confirm_password_edit)
        self.main_layout.addWidget(password_box)

        # --- Save Button ---
        self.save_btn = QPushButton("Save Changes")
        self.save_btn.clicked.connect(self._save_changes)
        self.main_layout.addWidget(self.save_btn)

    def _populate_data(self):
        """Populates the dialog with the user's current data."""
        self.username_label.setText(self.user.get('username', 'N/A'))
        self.email_edit.setText(self.user.get('email', ''))
        self.full_name_edit.setText(self.user.get('full_name') or "")
        age = self.user.get('age')
        self.age_edit.setText(str(age) if age is not None else "")
        self.job_title_combo.setCurrentText(self.user.get('job_title') or "")

        # Load avatar
        avatar_data = self.user.get('avatar')
        if avatar_data:
            pixmap = QPixmap()
            pixmap.loadFromData(avatar_data)
            self.avatar_label.setPixmap(pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        else:
            self.avatar_label.setText("No Avatar")

    def _change_avatar(self):
        """Opens a file dialog to select a new avatar image."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Avatar", "", "Image Files (*.png *.jpg *.jpeg *.bmp)", options=QFileDialog.Option.DontUseNativeDialog)
        if file_path:
            pixmap = QPixmap(file_path)
            self.avatar_label.setPixmap(pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))

    def _save_changes(self):
        """Validates input and saves all changes to the database."""
        try:
            # --- Save Profile Info ---
            new_email = self.email_edit.text().strip()
            if new_email and new_email != self.user.get('email'):
                database.update_user_email(self.user['id'], new_email)

            database.update_user_profile(
                self.user['id'],
                self.full_name_edit.text(),
                self.age_edit.text(),
                self.job_title_combo.currentText()
            )

            # --- Save Avatar ---
            pixmap = self.avatar_label.pixmap()
            if pixmap and not pixmap.isNull():
                buffer = QBuffer()
                buffer.open(QIODevice.OpenModeFlag.WriteOnly)
                # Save the pixmap directly to the buffer
                pixmap.save(buffer, "PNG")
                avatar_data = buffer.data()
                database.update_user_avatar(self.user['id'], avatar_data)

            # --- Save Password ---
            current_pass = self.current_password_edit.text()
            new_pass = self.new_password_edit.text()
            confirm_pass = self.confirm_password_edit.text()

            if current_pass or new_pass or confirm_pass:
                if not all([current_pass, new_pass, confirm_pass]):
                    raise ValueError("To change your password, you must fill in the current, new, and confirmation password fields.")

                verified_user = database.verify_user(self.user['username'], current_pass)
                if not verified_user:
                    raise ValueError("Current password is not correct.")
                if len(new_pass) < 8:
                    raise ValueError("New password must be at least 8 characters long.")
                if new_pass != confirm_pass:
                    raise ValueError("New passwords do not match.")

                database.update_user_password(self.user['id'], new_pass)

            QMessageBox.information(self, "Success", "Your profile has been updated successfully.")
            self.accept()

        except ValueError as ve:
            QMessageBox.warning(self, "Input Error", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
            logging.error(f"Error saving profile for user {self.user['id']}: {e}", exc_info=True)
