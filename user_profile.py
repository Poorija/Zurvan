import os
import logging
import pyotp
import qrcode
import io
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QFileDialog,
    QLabel, QMessageBox, QGroupBox, QComboBox, QCheckBox, QInputDialog
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

        # --- App Lock PIN Section ---
        pin_box = QGroupBox("App Lock PIN")
        pin_layout = QFormLayout(pin_box)
        self.new_pin_edit = QLineEdit()
        self.new_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pin_edit.setPlaceholderText("Enter a 4-8 digit PIN")
        self.confirm_pin_edit = QLineEdit()
        self.confirm_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pin_edit.setPlaceholderText("Confirm your new PIN")
        pin_layout.addRow("New PIN:", self.new_pin_edit)
        pin_layout.addRow("Confirm PIN:", self.confirm_pin_edit)
        set_pin_btn = QPushButton("Set/Change PIN")
        set_pin_btn.clicked.connect(self._handle_pin_change)
        pin_layout.addRow(set_pin_btn)
        self.main_layout.addWidget(pin_box)

        # --- OTP Section ---
        otp_box = QGroupBox("Two-Factor Authentication (OTP)")
        otp_layout = QVBoxLayout(otp_box)
        self.otp_checkbox = QCheckBox("Enable OTP for Login & App Lock")
        self.otp_checkbox.toggled.connect(self._handle_otp_toggle)
        setup_otp_btn = QPushButton("Setup/View QR Code")
        setup_otp_btn.clicked.connect(self._show_otp_setup_dialog)
        otp_layout.addWidget(self.otp_checkbox)
        otp_layout.addWidget(setup_otp_btn)
        self.main_layout.addWidget(otp_box)

        # --- Save Button ---
        self.save_btn = QPushButton("Save Profile Changes")
        self.save_btn.clicked.connect(self._save_changes)
        self.main_layout.addWidget(self.save_btn)

    def _populate_data(self):
        """Populates the dialog with the user's current data."""
        self.otp_checkbox.setChecked(bool(self.user.get('otp_secret')))
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

    def _handle_pin_change(self):
        """Validates and saves a new App Lock PIN after verifying the user's current password."""
        new_pin = self.new_pin_edit.text()
        confirm_pin = self.confirm_pin_edit.text()

        if not new_pin or not confirm_pin:
            QMessageBox.warning(self, "Input Error", "Please fill both PIN fields to set or change your PIN.")
            return

        if not new_pin.isdigit() or not (4 <= len(new_pin) <= 8):
            QMessageBox.warning(self, "Invalid PIN", "PIN must be between 4 and 8 digits.")
            return

        if new_pin != confirm_pin:
            QMessageBox.warning(self, "PIN Mismatch", "The entered PINs do not match.")
            return

        # --- Security Enhancement: Require current password ---
        password, ok = QInputDialog.getText(self, "Password Verification",
                                            "To change your PIN, please enter your current password:",
                                            QLineEdit.EchoMode.Password)
        if not ok or not password:
            return # User cancelled

        verified_user = database.verify_user(self.user['username'], password)
        if not verified_user:
            QMessageBox.critical(self, "Authentication Failed", "The password you entered is incorrect.")
            database.log_activity(
                user_id=self.user['id'], category='Profile', action='PIN Change',
                target=self.user['username'],
                details="Failed PIN change attempt due to incorrect password.",
                severity='High', result='Failure'
            )
            return
        # --- End Security Enhancement ---

        try:
            database.update_user_pin(self.user['id'], new_pin)
            # Log successful PIN change
            database.log_activity(
                user_id=self.user['id'],
                category='Profile',
                action='PIN Change',
                target=self.user['username'],
                details="User updated their App Lock PIN.",
                severity='Medium',
                result='Success'
            )
            QMessageBox.information(self, "Success", "Your App Lock PIN has been updated.")
            self.new_pin_edit.clear()
            self.confirm_pin_edit.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not update PIN: {e}")
            logging.error(f"Error updating PIN for user {self.user['id']}: {e}", exc_info=True)
            database.log_activity(
                user_id=self.user['id'],
                category='Profile',
                action='PIN Change',
                target=self.user['username'],
                details=f"Failed to update App Lock PIN. Error: {e}",
                severity='High',
                result='Failure'
            )


    def _save_changes(self):
        """Validates input and saves all changes to the database."""
        try:
            changes_made = []
            # --- Save Profile Info ---
            new_email = self.email_edit.text().strip()
            if new_email and new_email != self.user.get('email'):
                database.update_user_email(self.user['id'], new_email)
                changes_made.append(f"email to '{new_email}'")

            # Combine other profile fields
            new_full_name = self.full_name_edit.text()
            new_age = self.age_edit.text()
            new_job_title = self.job_title_combo.currentText()
            if (new_full_name != self.user.get('full_name') or
                str(new_age) != str(self.user.get('age') or '') or
                new_job_title != self.user.get('job_title')):
                database.update_user_profile(
                    self.user['id'], new_full_name, new_age, new_job_title
                )
                changes_made.append("profile details (name, age, job)")


            # --- Save Avatar ---
            pixmap = self.avatar_label.pixmap()
            # A bit tricky to see if avatar actually changed, but a new save implies it.
            # We check if there's a pixmap and if the original user data didn't have one, or just log it.
            # For simplicity, we log if a save happens.
            if pixmap and not pixmap.isNull():
                buffer = QBuffer()
                buffer.open(QIODevice.OpenModeFlag.WriteOnly)
                pixmap.save(buffer, "PNG")
                avatar_data = buffer.data()
                # Only log if the avatar data is actually different
                if avatar_data != self.user.get('avatar'):
                    database.update_user_avatar(self.user['id'], avatar_data)
                    changes_made.append("avatar")


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
                database.log_activity(
                    user_id=self.user['id'],
                    category='Profile',
                    action='Password Change',
                    target=self.user['username'],
                    details="User successfully changed their password.",
                    severity='High',
                    result='Success'
                )
                # No need to add to changes_made, it's a separate, more severe log entry

            # Log general profile updates if any were made
            if changes_made:
                database.log_activity(
                    user_id=self.user['id'],
                    category='Profile',
                    action='Profile Update',
                    target=self.user['username'],
                    details=f"Updated: {', '.join(changes_made)}.",
                    severity='Low',
                    result='Success'
                )


            QMessageBox.information(self, "Success", "Your profile has been updated successfully.")
            self.accept()

        except ValueError as ve:
            QMessageBox.warning(self, "Input Error", str(ve))
            # Log failed attempt
            database.log_activity(
                user_id=self.user['id'],
                category='Profile',
                action='Profile Update',
                target=self.user['username'],
                details=f"Failed profile update. Reason: {ve}",
                severity='Medium',
                result='Failure'
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
            logging.error(f"Error saving profile for user {self.user['id']}: {e}", exc_info=True)
            database.log_activity(
                user_id=self.user['id'],
                category='Profile',
                action='Profile Update',
                target=self.user['username'],
                details=f"Failed profile update. Error: {e}",
                severity='High',
                result='Failure'
            )

    def _handle_otp_toggle(self, checked):
        """Handles enabling or disabling OTP, requiring password verification for disabling."""
        if checked:
            # User wants to enable OTP, generate a secret if one doesn't exist
            if not self.user.get('otp_secret'):
                secret = pyotp.random_base32()
                database.set_otp_secret(self.user['id'], secret)
                self.user['otp_secret'] = secret # Update local user dict
                database.log_activity(
                    user_id=self.user['id'], category='Profile', action='OTP Enabled',
                    target=self.user['username'],
                    details="User enabled two-factor authentication.",
                    severity='High', result='Success'
                )
                self._show_otp_setup_dialog(is_initial_setup=True)
        else:
            # User wants to disable OTP, require password verification first.
            password, ok = QInputDialog.getText(self, "Password Verification",
                                            "To disable OTP, please enter your current password:",
                                            QLineEdit.EchoMode.Password)
            if not ok or not password:
                self.otp_checkbox.setChecked(True) # Revert checkbox if user cancels
                return

            verified_user = database.verify_user(self.user['username'], password)
            if not verified_user:
                QMessageBox.critical(self, "Authentication Failed", "The password you entered is incorrect. OTP remains active.")
                database.log_activity(
                    user_id=self.user['id'], category='Profile', action='OTP Disabled',
                    target=self.user['username'],
                    details="Failed OTP disable attempt due to incorrect password.",
                    severity='High', result='Failure'
                )
                self.otp_checkbox.setChecked(True) # Revert checkbox
                return

            # If password is correct, proceed with disabling OTP
            database.set_otp_secret(self.user['id'], None)
            self.user['otp_secret'] = None
            database.log_activity(
                user_id=self.user['id'], category='Profile', action='OTP Disabled',
                target=self.user['username'],
                details="User disabled two-factor authentication after successful password verification.",
                severity='High', result='Success'
            )
            QMessageBox.information(self, "OTP Disabled", "Two-factor authentication has been disabled.")

    def _show_otp_setup_dialog(self, is_initial_setup=False):
        """Shows a dialog with the OTP QR code and secret."""
        secret = self.user.get('otp_secret')
        if not secret:
            if is_initial_setup: # This path is taken by _handle_otp_toggle
                 # Should have been set already, but as a fallback:
                secret = pyotp.random_base32()
                database.set_otp_secret(self.user['id'], secret)
                self.user['otp_secret'] = secret
            else:
                QMessageBox.information(self, "OTP Not Enabled", "Please enable OTP first to view the setup code.")
                return

        dialog = QDialog(self)
        dialog.setWindowTitle("Two-Factor Authentication Setup")
        layout = QVBoxLayout(dialog)

        if is_initial_setup:
            layout.addWidget(QLabel("Scan the QR code with your authenticator app (e.g., Google Authenticator)."))
            layout.addWidget(QLabel("This code will only be shown once."))
        else:
            layout.addWidget(QLabel("Scan this QR code with your authenticator app."))

        # Generate QR code
        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.user.get('email'),
            issuer_name="Zurvan App"
        )
        qr_img = qrcode.make(otp_uri)
        img_byte_array = io.BytesIO()
        qr_img.save(img_byte_array, format='PNG')
        pixmap = QPixmap()
        pixmap.loadFromData(img_byte_array.getvalue())

        qr_label = QLabel()
        qr_label.setPixmap(pixmap)
        layout.addWidget(qr_label, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(QLabel(f"Or manually enter this secret: {secret}"))

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(dialog.accept)
        layout.addWidget(ok_button)

        dialog.exec()
