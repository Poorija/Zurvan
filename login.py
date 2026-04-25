import sys
import random
import os
import re
from PyQt6.QtWidgets import (
    QApplication, QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QStackedWidget, QFormLayout, QMessageBox, QGroupBox, QComboBox,
    QGraphicsOpacityEffect, QCheckBox, QProgressBar
)
from theme_support import apply_stylesheet, list_themes
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer
from PyQt6.QtGui import QIcon, QPixmap
import database
import logging
import pyotp
import qrcode
import io
from captcha import generate_captcha

# This list must be kept in sync with the one in database.py
SECURITY_QUESTIONS_LIST = [
    "What was your first pet's name?", "What is your mother's maiden name?",
    "What was the name of your elementary school?", "What city were you born in?",
    "What is your favorite book?", "What was the model of your first car?",
    "What is your favorite movie?", "What is your favorite food?",
    "What is the name of your best childhood friend?", "In what city did you meet your spouse/partner?",
    "What is your favorite sports team?", "What was your high school mascot?",
    "What is the name of the street you grew up on?", "What is your favorite color?",
    "What is your father's middle name?"
]

class PasswordResetDialog(QDialog):
    """A dialog to handle the multi-step password reset process."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Reset Password")
        self.setModal(True)
        self.setMinimumWidth(450)
        self.user_data = None  # To store the user's full data record

        main_layout = QVBoxLayout(self)
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        # Create pages for the reset process
        self.page1_identifier = self._create_identifier_page()
        self.page2_questions = self._create_questions_page()
        self.page3_new_password = self._create_new_password_page()

        self.stacked_widget.addWidget(self.page1_identifier)
        self.stacked_widget.addWidget(self.page2_questions)
        self.stacked_widget.addWidget(self.page3_new_password)

        self.adjustSize()

    def _create_identifier_page(self):
        page = QWidget()
        layout = QFormLayout(page)
        layout.setVerticalSpacing(15)
        self.identifier_edit = QLineEdit()
        self.identifier_edit.setPlaceholderText("Enter your username or email")
        layout.addRow("Username or Email:", self.identifier_edit)

        continue_btn = QPushButton("Continue")
        continue_btn.clicked.connect(self._handle_find_user)
        layout.addRow(continue_btn)
        return page

    def _create_questions_page(self):
        page = QWidget()
        self.questions_layout = QFormLayout(page)
        self.questions_layout.setVerticalSpacing(15)
        self.questions_layout.addRow(QLabel("Please answer your security questions:"))
        return page

    def _create_new_password_page(self):
        page = QWidget()
        layout = QFormLayout(page)
        layout.setVerticalSpacing(15)
        self.new_pass_edit = QLineEdit()
        self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pass_edit = QLineEdit()
        self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)

        # New Password field with toggle
        new_pass_container = QWidget()
        new_pass_layout = QHBoxLayout(new_pass_container)
        new_pass_layout.setContentsMargins(0,0,0,0)
        new_pass_layout.addWidget(self.new_pass_edit)
        new_pass_toggle_button = QPushButton()
        new_pass_toggle_button.setCheckable(True)
        new_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        new_pass_toggle_button.setChecked(False)
        new_pass_toggle_button.setFixedSize(28, 28)
        new_pass_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        new_pass_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_new_pass_visibility(checked):
            if checked:
                self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                new_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
                new_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        new_pass_toggle_button.toggled.connect(toggle_new_pass_visibility)
        new_pass_layout.addWidget(new_pass_toggle_button)
        layout.addRow("New Password:", new_pass_container)

        # Confirm New Password field with toggle
        confirm_pass_container = QWidget()
        confirm_pass_layout = QHBoxLayout(confirm_pass_container)
        confirm_pass_layout.setContentsMargins(0,0,0,0)
        confirm_pass_layout.addWidget(self.confirm_pass_edit)
        confirm_pass_toggle_button = QPushButton()
        confirm_pass_toggle_button.setCheckable(True)
        confirm_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        confirm_pass_toggle_button.setChecked(False)
        confirm_pass_toggle_button.setFixedSize(28, 28)
        confirm_pass_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        confirm_pass_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_confirm_pass_visibility(checked):
            if checked:
                self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                confirm_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
                confirm_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        confirm_pass_toggle_button.toggled.connect(toggle_confirm_pass_visibility)
        confirm_pass_layout.addWidget(confirm_pass_toggle_button)
        layout.addRow("Confirm Password:", confirm_pass_container)

        reset_btn = QPushButton("Reset Password")
        reset_btn.clicked.connect(self._handle_set_new_password)
        layout.addRow(reset_btn)
        return page

    def _handle_find_user(self):
        identifier = self.identifier_edit.text().strip()
        if not identifier:
            QMessageBox.warning(self, "Input Error", "Please enter a username or email.")
            return

        user = database.get_user_by_username_or_email(identifier)
        if not user:
            QMessageBox.warning(self, "Not Found", "No active user found with that username or email.")
            return

        self.user_data = dict(user)
        question_ids = database.get_user_security_questions(self.user_data['id'])

        if not question_ids or len(question_ids) < 3:
            QMessageBox.critical(self, "Recovery Error", "This account does not have sufficient security questions set up for recovery.")
            return

        # Dynamically build the questions page
        while self.questions_layout.count() > 1: # Keep the title label
            self.questions_layout.removeRow(1)

        self.answer_widgets = []
        for q_id in question_ids:
            question_text = SECURITY_QUESTIONS_LIST[q_id]
            answer_edit = QLineEdit()
            self.questions_layout.addRow(QLabel(question_text), answer_edit)
            self.answer_widgets.append({'id': q_id, 'edit': answer_edit})

        verify_btn = QPushButton("Verify Answers")
        verify_btn.clicked.connect(self._handle_verify_answers)
        self.questions_layout.addRow(verify_btn)

        self.stacked_widget.setCurrentWidget(self.page2_questions)
        self.adjustSize()

    def _handle_verify_answers(self):
        answers_dict = {item['id']: item['edit'].text() for item in self.answer_widgets}

        if not all(answers_dict.values()):
            QMessageBox.warning(self, "Input Error", "Please answer all security questions.")
            return

        if database.verify_security_answers(self.user_data['id'], answers_dict):
            self.stacked_widget.setCurrentWidget(self.page3_new_password)
            self.adjustSize()
        else:
            QMessageBox.warning(self, "Verification Failed", "One or more answers were incorrect. Please try again.")

    def _handle_set_new_password(self):
        new_pass = self.new_pass_edit.text()
        confirm_pass = self.confirm_pass_edit.text()

        if not new_pass or not confirm_pass:
            QMessageBox.warning(self, "Input Error", "Please fill out both password fields.")
            return
        if len(new_pass) < 8:
            QMessageBox.warning(self, "Input Error", "Password must be at least 8 characters long.")
            return
        if new_pass != confirm_pass:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
            return

        try:
            database.update_user_password(self.user_data['id'], new_pass)
            QMessageBox.information(self, "Success", "Your password has been reset successfully. You can now log in.")
            self.accept() # Close the reset dialog
        except Exception as e:
            logging.error(f"Error updating password: {e}", exc_info=True)
            QMessageBox.critical(self, "Database Error", "An unexpected error occurred while updating the password. Please try again later.")


class ForcePasswordChangeDialog(QDialog):
    """A dialog to force a user to change their default password."""
    def __init__(self, user_id, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Password Required")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.user_id = user_id
        # Prevent closing the dialog with the 'X' button
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint)

        layout = QFormLayout(self)
        layout.setVerticalSpacing(15)

        layout.addRow(QLabel("For security, you must change your default password before proceeding."))

        self.new_pass_edit = QLineEdit()
        self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pass_edit = QLineEdit()
        self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)

        # New Password field with toggle
        new_pass_container = QWidget()
        new_pass_layout = QHBoxLayout(new_pass_container)
        new_pass_layout.setContentsMargins(0,0,0,0)
        new_pass_layout.addWidget(self.new_pass_edit)
        new_pass_toggle_button = QPushButton()
        new_pass_toggle_button.setCheckable(True)
        new_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        new_pass_toggle_button.setChecked(False)
        new_pass_toggle_button.setFixedSize(28, 28)
        new_pass_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        new_pass_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_new_pass_visibility(checked):
            if checked:
                self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                new_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
                new_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        new_pass_toggle_button.toggled.connect(toggle_new_pass_visibility)
        new_pass_layout.addWidget(new_pass_toggle_button)
        layout.addRow("New Password:", new_pass_container)

        # Confirm New Password field with toggle
        confirm_pass_container = QWidget()
        confirm_pass_layout = QHBoxLayout(confirm_pass_container)
        confirm_pass_layout.setContentsMargins(0,0,0,0)
        confirm_pass_layout.addWidget(self.confirm_pass_edit)
        confirm_pass_toggle_button = QPushButton()
        confirm_pass_toggle_button.setCheckable(True)
        confirm_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        confirm_pass_toggle_button.setChecked(False)
        confirm_pass_toggle_button.setFixedSize(28, 28)
        confirm_pass_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        confirm_pass_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_confirm_pass_visibility(checked):
            if checked:
                self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                confirm_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
                confirm_pass_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        confirm_pass_toggle_button.toggled.connect(toggle_confirm_pass_visibility)
        confirm_pass_layout.addWidget(confirm_pass_toggle_button)
        layout.addRow("Confirm Password:", confirm_pass_container)

        set_password_btn = QPushButton("Set New Password")
        set_password_btn.clicked.connect(self._handle_set_new_password)
        layout.addRow(set_password_btn)

    def _handle_set_new_password(self):
        new_pass = self.new_pass_edit.text()
        confirm_pass = self.confirm_pass_edit.text()

        if new_pass == "P@ssw0rd1234567890":
            QMessageBox.warning(self, "Input Error", "The new password cannot be the same as the default password.")
            return
        if not new_pass or not confirm_pass:
            QMessageBox.warning(self, "Input Error", "Please fill out both password fields.")
            return
        if len(new_pass) < 8:
            QMessageBox.warning(self, "Input Error", "Password must be at least 8 characters long.")
            return
        if new_pass != confirm_pass:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
            return

        try:
            database.update_user_password(self.user_id, new_pass)
            QMessageBox.information(self, "Success", "Your password has been changed successfully.")
            self.accept() # Close the dialog
        except Exception as e:
            logging.error(f"Error forcing password change: {e}", exc_info=True)
            QMessageBox.critical(self, "Database Error", "An unexpected error occurred. Please try again later.")

    def closeEvent(self, event):
        # Override the close event to prevent the dialog from closing
        event.ignore()


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Zurvan - Login")
        self.setModal(True)
        self.current_user = None
        self.selected_theme = 'dark_cyan.xml' # Default theme
        self.captcha_text = None
        self.reg_captcha_text = None

        # --- Main Layout and Styling ---
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.setSpacing(20)
        # Set a base background color that matches the dark themes
        self.setStyleSheet("QDialog { background-color: #2b2b2b; }")

        # --- Header Section ---
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget) # Changed to QHBoxLayout
        header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.setSpacing(20)

        # Logo
        self.logo_label = QLabel()
        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_path = os.path.join(script_dir, "icons", "Zurvan.png")
        pixmap = QPixmap(icon_path)
        self.logo_label.setPixmap(pixmap.scaled(180, 180, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        header_layout.addWidget(self.logo_label)

        # Text container
        text_widget = QWidget()
        text_layout = QVBoxLayout(text_widget)
        text_layout.setContentsMargins(0,0,0,0)
        text_layout.setSpacing(5)

        # App Name
        app_name_label = QLabel("Zurvan")
        app_name_label.setStyleSheet("font-size: 28px; font-weight: bold; color: #cccccc;")
        app_name_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        text_layout.addWidget(app_name_label)

        # Slogan
        slogan_label = QLabel("Your All-in-One Penetration Testing Toolkit.")
        slogan_label.setStyleSheet("font-size: 16px; color: #999999;")
        slogan_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        text_layout.addWidget(slogan_label)

        header_layout.addWidget(text_widget)
        header_layout.addStretch()

        main_layout.addWidget(header_widget)

        # --- Stacked Widget for Login/Register ---
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        # Make the stacked widget blend in
        self.stacked_widget.setStyleSheet("QStackedWidget { background-color: transparent; }")

        self.login_page = self._create_login_page()
        self.register_page = self._create_register_page()

        # Create all pages first
        self.login_page = self._create_login_page()
        self.admin_login_page = self._create_admin_login_page()
        self.register_page = self._create_register_page()

        # Create the inner stack for login/admin-login
        self.login_page_stack = QStackedWidget()
        self.login_page_stack.addWidget(self.login_page)
        self.login_page_stack.addWidget(self.admin_login_page)

        # Add the two main views (the login stack and the register page) to the main stacked widget
        self.stacked_widget.addWidget(self.login_page_stack)
        self.stacked_widget.addWidget(self.register_page)
        self.stacked_widget.currentChanged.connect(self.adjustSize) # Adjust size when switching pages

        self.lockout_end_time = None
        self.lockout_timer = QTimer(self)
        self.lockout_timer.timeout.connect(self._update_lockout_timer)

        self.setMinimumSize(500, 750) # Increased height for new widgets
        self.adjustSize()

        # --- Animation & Initial State ---
        self.start_logo_animation()
        self._refresh_captcha('login') # Load the first captcha for login page

    def _handle_password_reset_request(self):
        """Opens the password reset dialog."""
        reset_dialog = PasswordResetDialog(self)
        reset_dialog.exec()

    def _handle_theme_change(self, theme_name):
        """Applies the selected theme to the entire application."""
        self.selected_theme = f"{theme_name}.xml"
        # This dictionary should be kept in sync with the one in zurvan.py
        extra_qss = {
            'QGroupBox': {
                'border': '1px solid #444;',
                'border-radius': '8px',
                'margin-top': '10px',
            },
            'QGroupBox::title': {
                'subcontrol-origin': 'margin',
                'subcontrol-position': 'top left',
                'padding': '0 10px',
            },
            'QTabWidget::pane': {
                'border-top': '1px solid #444;',
                'margin-top': '-1px',
            },
            'QFrame': {
                'border-radius': '8px',
            },
            'QPushButton': {
                'border-radius': '8px',
            },
            'QLineEdit': {
                'border-radius': '8px',
            },
            'QComboBox': {
                'border-radius': '8px',
            },
            'QTextEdit': {
                'border-radius': '8px',
            },
            'QPlainTextEdit': {
                'border-radius': '8px',
            },
            'QListWidget': {
                'border-radius': '8px',
            },
            'QTreeWidget': {
                'border-radius': '8px',
            }
        }
        apply_stylesheet(QApplication.instance(), theme=self.selected_theme, extra=extra_qss)

    def start_logo_animation(self):
        """Creates and starts a fade-in animation for the logo."""
        self.opacity_effect = QGraphicsOpacityEffect(self.logo_label)
        self.logo_label.setGraphicsEffect(self.opacity_effect)
        self.animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.animation.setDuration(1500) # 1.5 seconds
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.animation.start()

    def _show_tos_popup(self, link):
        """Displays the Terms of Service in a pop-up dialog."""
        tos_text = """
        <h2>Terms of Service for Zurvan</h2>
        <p><strong>Last Updated: September 22, 2025</strong></p>
        <p>Welcome to Zurvan! These terms and conditions outline the rules and regulations for the use of this software.</p>

        <h3>1. Acceptance of Terms</h3>
        <p>By accessing and using this software, you accept and agree to be bound by the terms and provision of this agreement. If you do not agree to abide by these terms, please do not use this software.</p>

        <h3>2. Disclaimer of Liability</h3>
        <p>Zurvan is a tool designed for network analysis and security research. The user acknowledges that any actions and or activities related to the use of Zurvan are the sole responsibility of the user. The developers of Zurvan assume no liability and are not responsible for any misuse or damage caused by this program. It is the end user's responsibility to obey all applicable local, state, and federal laws. This tool is intended for educational and professional purposes ONLY.</p>

        <h3>3. Prohibited Use</h3>
        <p>You agree not to use the software for any unlawful purpose or any purpose prohibited under this clause. You agree not to use the software in any way that could damage the software, services, or general business of the developers.</p>

        <h3>4. Changes to Terms</h3>
        <p>We reserve the right to modify these terms at any time. We will notify you of any changes by posting the new Terms of Service in this software. You are advised to review these Terms of Service periodically for any changes.</p>
        """
        tos_dialog = QMessageBox(self)
        tos_dialog.setWindowTitle("Terms of Service")
        tos_dialog.setTextFormat(Qt.TextFormat.RichText)
        tos_dialog.setText(tos_text)
        tos_dialog.setIcon(QMessageBox.Icon.Information)
        tos_dialog.exec()

    def _refresh_captcha(self, context='login'):
        """Generates a new captcha and updates the UI for the given context."""
        try:
            pixmap, text = generate_captcha()
            if context == 'login':
                self.captcha_image_label.setPixmap(pixmap)
                self.captcha_text = text
            elif context == 'register':
                self.reg_captcha_image_label.setPixmap(pixmap)
                self.reg_captcha_text = text
        except Exception:
            error_message = "Captcha Failed"
            fallback_text = "fallback"
            if context == 'login':
                self.captcha_image_label.setText(error_message)
                self.captcha_text = fallback_text
            elif context == 'register':
                self.reg_captcha_image_label.setText(error_message)
                self.reg_captcha_text = fallback_text
            logging.error("Failed to generate captcha", exc_info=True)

    def _create_login_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        login_box = QGroupBox("User Login")
        login_box.setStyleSheet("QGroupBox { border: 1px solid #444; padding: 15px; }")

        self.login_form_layout = QFormLayout(login_box)
        self.login_form_layout.setVerticalSpacing(20)

        # --- Lockout UI ---
        self.lockout_widget = QWidget()
        lockout_layout = QHBoxLayout(self.lockout_widget)
        self.lockout_icon_label = QLabel()
        self.lockout_icon_label.setPixmap(QIcon.fromTheme("dialog-error", QIcon("icons/Zurvan-mono.png")).pixmap(24, 24))
        self.lockout_label = QLabel()
        lockout_layout.addWidget(self.lockout_icon_label)
        lockout_layout.addWidget(self.lockout_label)
        self.lockout_widget.setVisible(False) # Hidden by default
        self.login_form_layout.addRow(self.lockout_widget)

        self.login_username_edit = QLineEdit()
        self.login_password_edit = QLineEdit()
        self.login_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_form_layout.addRow("Username:", self.login_username_edit)

        # Password field with toggle button
        password_container = QWidget()
        password_layout = QHBoxLayout(password_container)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.addWidget(self.login_password_edit)

        toggle_button = QPushButton()
        toggle_button.setCheckable(True)
        toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        toggle_button.setChecked(False)
        toggle_button.setFixedSize(28, 28)
        toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")

        def toggle_login_password_visibility(checked):
            if checked:
                self.login_password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.login_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
                toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))

        toggle_button.toggled.connect(toggle_login_password_visibility)
        password_layout.addWidget(toggle_button)
        self.login_form_layout.addRow("Password:", password_container)

        # --- Login Method Switcher ---
        self.login_method_combo = QComboBox()
        self.login_method_combo.addItems(["Captcha", "OTP"])
        self.login_method_combo.currentTextChanged.connect(self._update_login_method_view)
        self.login_form_layout.addRow("Login Method:", self.login_method_combo)

        # --- OTP ---
        self.login_otp_edit = QLineEdit()
        self.login_otp_edit.setPlaceholderText("One-Time Password (if enabled)")
        self.otp_row_widget = QWidget() # Create a container widget
        otp_layout = QHBoxLayout(self.otp_row_widget)
        otp_layout.setContentsMargins(0,0,0,0)
        otp_layout.addWidget(self.login_otp_edit)
        self.login_form_layout.addRow("OTP:", self.otp_row_widget)

        # --- Captcha ---
        self.captcha_container_widget = QWidget() # Container for the whole captcha row
        captcha_container_layout = QFormLayout(self.captcha_container_widget)
        captcha_container_layout.setContentsMargins(0,0,0,0)

        self.captcha_image_label = QLabel("Captcha loading...")
        self.captcha_input_edit = QLineEdit()
        self.captcha_input_edit.setPlaceholderText("Enter Captcha Text")
        refresh_captcha_btn = QPushButton(" Regenerate")
        refresh_captcha_btn.setIcon(QIcon.fromTheme("view-refresh", QIcon("icons/refresh-cw.svg")))
        refresh_captcha_btn.clicked.connect(lambda: self._refresh_captcha('login'))

        captcha_group_layout = QHBoxLayout()
        captcha_group_layout.addWidget(self.captcha_image_label, 2)
        captcha_group_layout.addWidget(self.captcha_input_edit, 2)
        captcha_group_layout.addWidget(refresh_captcha_btn, 1)

        # Add the QHBoxLayout to the container's QFormLayout
        captcha_container_layout.addRow("Captcha:", captcha_group_layout)
        self.login_form_layout.addRow(self.captcha_container_widget)

        # Set initial visibility based on the switcher
        self._update_login_method_view(self.login_method_combo.currentText())

        # --- Theme Selector ---
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([theme.replace('.xml', '') for theme in list_themes()])
        self.theme_combo.setCurrentText(self.selected_theme.replace('.xml', ''))
        self.theme_combo.textActivated.connect(self._handle_theme_change)
        self.login_form_layout.addRow("Theme:", self.theme_combo)

        self.login_button = QPushButton("Login")
        self.login_button.setMaximumWidth(200)
        self.login_button.clicked.connect(self._handle_login)
        self.login_form_layout.addRow(self.login_button)

        self.links_widget = QWidget() # Put links in a container to hide them
        links_layout = QHBoxLayout(self.links_widget)
        register_link = QLabel("<a href='#'>Register a new account</a>")
        register_link.linkActivated.connect(lambda: self.stacked_widget.setCurrentWidget(self.register_page))
        forgot_password_link = QLabel("<a href='#'>Forgot Password?</a>")
        forgot_password_link.linkActivated.connect(self._handle_password_reset_request)
        links_layout.addWidget(register_link)
        links_layout.addStretch()
        links_layout.addWidget(forgot_password_link)
        self.login_form_layout.addRow(self.links_widget)

        # --- Admin Override Checkbox ---
        admin_override_checkbox = QCheckBox("I'm an Administrator")
        admin_override_checkbox.toggled.connect(lambda checked: self.login_page_stack.setCurrentIndex(1 if checked else 0))
        self.login_form_layout.addRow(admin_override_checkbox)

        layout.addWidget(login_box)
        return page

    def _update_login_method_view(self, method):
        """Controls the visibility and appearance of login fields based on the selected method."""
        is_captcha_method = (method == "Captcha")

        # Toggle visibility
        self.captcha_container_widget.setVisible(is_captcha_method)
        self.otp_row_widget.setVisible(not is_captcha_method)

        # Adjust opacity for better UX
        captcha_opacity = 1.0 if is_captcha_method else 0.5
        otp_opacity = 1.0 if not is_captcha_method else 0.5

        captcha_effect = QGraphicsOpacityEffect(self.captcha_container_widget)
        captcha_effect.setOpacity(captcha_opacity)
        self.captcha_container_widget.setGraphicsEffect(captcha_effect)
        self.captcha_container_widget.setEnabled(is_captcha_method)

        otp_effect = QGraphicsOpacityEffect(self.otp_row_widget)
        otp_effect.setOpacity(otp_opacity)
        self.otp_row_widget.setGraphicsEffect(otp_effect)
        self.otp_row_widget.setEnabled(not is_captcha_method)


    def _create_register_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        register_box = QGroupBox("Create New Account")
        register_box.setStyleSheet("QGroupBox { border: 1px solid #444; padding: 15px; }")
        form_layout = QFormLayout(register_box)
        form_layout.setVerticalSpacing(20)

        self.reg_username_edit = QLineEdit()
        self.reg_email_edit = QLineEdit()
        self.reg_password_edit = QLineEdit()
        self.reg_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm_password_edit = QLineEdit()
        self.reg_confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Username:", self.reg_username_edit)
        form_layout.addRow("Email:", self.reg_email_edit)

        # Password field with toggle
        reg_password_container = QWidget()
        reg_password_layout = QHBoxLayout(reg_password_container)
        reg_password_layout.setContentsMargins(0,0,0,0)
        reg_password_layout.addWidget(self.reg_password_edit)
        reg_toggle_button = QPushButton()
        reg_toggle_button.setCheckable(True)
        reg_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        reg_toggle_button.setChecked(False)
        reg_toggle_button.setFixedSize(28, 28)
        reg_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        reg_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_reg_password_visibility(checked):
            if checked:
                self.reg_password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                reg_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.reg_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
                reg_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        reg_toggle_button.toggled.connect(toggle_reg_password_visibility)
        reg_password_layout.addWidget(reg_toggle_button)
        form_layout.addRow("Password:", reg_password_container)

        # Confirm Password field with toggle
        reg_confirm_container = QWidget()
        reg_confirm_layout = QHBoxLayout(reg_confirm_container)
        reg_confirm_layout.setContentsMargins(0,0,0,0)
        reg_confirm_layout.addWidget(self.reg_confirm_password_edit)
        reg_confirm_toggle_button = QPushButton()
        reg_confirm_toggle_button.setCheckable(True)
        reg_confirm_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        reg_confirm_toggle_button.setChecked(False)
        reg_confirm_toggle_button.setFixedSize(28, 28)
        reg_confirm_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        reg_confirm_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_reg_confirm_password_visibility(checked):
            if checked:
                self.reg_confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                reg_confirm_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.reg_confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
                reg_confirm_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        reg_confirm_toggle_button.toggled.connect(toggle_reg_confirm_password_visibility)
        reg_confirm_layout.addWidget(reg_confirm_toggle_button)
        form_layout.addRow("Confirm Password:", reg_confirm_container)

        # --- Password Strength Meter ---
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 3) # One point for each criterion
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.requirements_label = QLabel()

        # Use a container widget to hold the bar and label
        strength_container = QWidget()
        strength_layout = QVBoxLayout(strength_container)
        strength_layout.setContentsMargins(0, 5, 0, 0)
        strength_layout.setSpacing(5)
        strength_layout.addWidget(self.strength_bar)
        strength_layout.addWidget(self.requirements_label)
        form_layout.addRow("Password Strength:", strength_container)

        # Connect signal and set initial state
        self.reg_password_edit.textChanged.connect(self._update_password_strength)
        self._update_password_strength("") # Set initial empty state

        # --- Security Questions ---
        self.security_questions_widgets = []
        questions_box = QGroupBox("Security Questions (Choose 3)")
        questions_layout = QFormLayout(questions_box)

        available_questions = list(enumerate(SECURITY_QUESTIONS_LIST))

        # Create and connect security question widgets
        initial_indices = random.sample(range(len(SECURITY_QUESTIONS_LIST)), 3)
        for i in range(3):
            q_combo = QComboBox()
            a_edit = QLineEdit()
            a_edit.setPlaceholderText(f"Answer for question {i+1}")
            questions_layout.addRow(f"Question {i+1}:", q_combo)
            questions_layout.addRow(f"Answer {i+1}:", a_edit)
            widget_data = {'combo': q_combo, 'answer': a_edit, 'initial_index': initial_indices[i]}
            self.security_questions_widgets.append(widget_data)
            q_combo.currentIndexChanged.connect(self._update_security_questions)

        self._set_initial_questions()
        form_layout.addRow(questions_box)

        # --- Captcha ---
        self.reg_captcha_image_label = QLabel("Captcha loading...")
        self.reg_captcha_input_edit = QLineEdit()
        self.reg_captcha_input_edit.setPlaceholderText("Enter Captcha Text")
        reg_refresh_captcha_btn = QPushButton(" Regenerate")
        reg_refresh_captcha_btn.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'refresh-cw.svg')))
        reg_refresh_captcha_btn.clicked.connect(lambda: self._refresh_captcha('register'))

        reg_captcha_layout = QHBoxLayout()
        reg_captcha_layout.addWidget(self.reg_captcha_image_label, 2)
        reg_captcha_layout.addWidget(self.reg_captcha_input_edit, 2)
        reg_captcha_layout.addWidget(reg_refresh_captcha_btn, 1)
        form_layout.addRow("Captcha:", reg_captcha_layout)
        self._refresh_captcha('register') # Load initial captcha for register page

        # --- OTP and Terms of Service ---
        options_container = QWidget()
        options_layout = QHBoxLayout(options_container)
        options_layout.setContentsMargins(0, 5, 0, 0)

        self.enable_otp_checkbox = QCheckBox("Enable 2FA (OTP)")
        self.tos_checkbox = QCheckBox()
        tos_label = QLabel("I agree to the <a href='#'>Terms of Service</a>")
        tos_label.setOpenExternalLinks(False)
        tos_label.linkActivated.connect(self._show_tos_popup)

        options_layout.addWidget(self.enable_otp_checkbox)
        options_layout.addStretch()
        options_layout.addWidget(self.tos_checkbox)
        options_layout.addWidget(tos_label)
        options_layout.addStretch()
        form_layout.addRow("", options_container)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self._handle_register)
        form_layout.addRow(register_button)

        back_to_login_link = QLabel("<a href='#'>Back to Login</a>")
        back_to_login_link.linkActivated.connect(lambda: self.stacked_widget.setCurrentWidget(self.login_page_stack))
        form_layout.addRow(back_to_login_link)

        layout.addWidget(register_box)
        return page

    def _set_initial_questions(self):
        """Populates the combo boxes with all questions and sets unique initial selections."""
        for widget_item in self.security_questions_widgets:
            combo = widget_item['combo']
            combo.blockSignals(True)
            for q_id, q_text in enumerate(SECURITY_QUESTIONS_LIST):
                combo.addItem(q_text, userData=q_id)
            # Set a unique index from the pre-selected random sample
            combo.setCurrentIndex(widget_item['initial_index'])
            combo.blockSignals(False)
        # Trigger the first update to filter the lists correctly
        self._update_security_questions()

    def _update_security_questions(self):
        """
        Updates all security question combo boxes to ensure no duplicate
        questions can be selected, while preserving the current selection
        of each box if possible.
        """
        # Get all currently selected question IDs
        selected_ids = {w['combo'].currentData() for w in self.security_questions_widgets if w['combo'].count() > 0}

        for widget_item in self.security_questions_widgets:
            combo = widget_item['combo']
            current_id_for_this_combo = combo.currentData()

            combo.blockSignals(True)
            combo.clear()

            new_index_to_set = -1
            # Repopulate with available questions
            for q_id, q_text in enumerate(SECURITY_QUESTIONS_LIST):
                # An item is available if it's not selected by another box,
                # OR if it's the item currently selected by this specific box.
                if q_id not in selected_ids or q_id == current_id_for_this_combo:
                    combo.addItem(q_text, userData=q_id)
                    if q_id == current_id_for_this_combo:
                        new_index_to_set = combo.count() - 1

            if new_index_to_set != -1:
                combo.setCurrentIndex(new_index_to_set)

            combo.blockSignals(False)

    def _update_password_strength(self, password):
        """Checks password complexity and updates UI elements in real-time."""
        has_length = len(password) >= 6
        has_digit = any(c.isdigit() for c in password)
        special_chars = r"!@#$%^&*()_+-=[]{}|;':,./<>?"
        has_special = any(c in special_chars for c in password)

        criteria_met = [has_length, has_digit, has_special]
        score = sum(criteria_met)

        # Build requirements text with colors
        reqs = {
            "✓ At least 6 characters": has_length,
            "✓ At least one number": has_digit,
            "✓ At least one special character": has_special
        }
        req_html = []
        for text, met in reqs.items():
            color = "green" if met else "#888888"
            # Replace checkmark with a dash if not met
            display_text = text if met else text.replace('✓', '-')
            req_html.append(f"<font color='{color}'>{display_text}</font>")
        self.requirements_label.setText("<br>".join(req_html))

        # Update progress bar value and color
        self.strength_bar.setValue(score)
        if score == 0:
            color = "#2b2b2b"
        elif score == 1:
            color = "red"
        elif score == 2:
            color = "orange"
        else: # score == 3
            color = "green"

        self.strength_bar.setStyleSheet(f'''
            QProgressBar {{
                border: 1px solid #444;
                border-radius: 4px;
                background-color: #2b2b2b;
                text-align: center;
                height: 10px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
        ''')

    def _handle_login(self):
        username = self.login_username_edit.text().strip()
        password = self.login_password_edit.text()
        captcha_input = self.captcha_input_edit.text().strip()

        if not username or not password or not captcha_input:
            QMessageBox.warning(self, "Input Error", "Username, password, and captcha are required.")
            return

        # Case-insensitive captcha check
        if captcha_input.upper() != self.captcha_text.upper():
            QMessageBox.warning(self, "Login Failed", "Incorrect captcha. Please try again.")
            database.register_failed_login_attempt(username)
            self._refresh_captcha()
            self.captcha_input_edit.clear()
            # We must now check if this failed attempt caused a lockout
            user_or_status = database.verify_user(username, "") # We pass an empty pass to re-check status
            if isinstance(user_or_status, str) and user_or_status.startswith('locked:'):
                 self._handle_lockout_message(user_or_status)
            return

    def _handle_lockout_message(self, status_string):
        """Parses a lockout status string and shows a formatted message box."""
        from datetime import datetime
        try:
            timestamp_str = status_string.split(':', 1)[1]
            self.lockout_end_time = datetime.fromisoformat(timestamp_str)
            self._set_login_form_enabled(False)
            self.lockout_timer.start(1000) # Update every second
            self._update_lockout_timer() # Initial call to show time immediately
            self.lockout_widget.setVisible(True)
        except (IndexError, ValueError) as e:
             QMessageBox.warning(self, "Account Locked", "This account is temporarily locked.")
             logging.error(f"Could not parse lockout timestamp: {e}")

    def _update_lockout_timer(self):
        """Called by the QTimer to update the lockout countdown."""
        from datetime import datetime
        if self.lockout_end_time and self.lockout_end_time > datetime.now():
            remaining = self.lockout_end_time - datetime.now()
            remaining_minutes = max(0, remaining.seconds // 60)
            remaining_seconds = max(0, remaining.seconds % 60)
            self.lockout_label.setText(f"Account locked. Try again in {remaining_minutes:02d}:{remaining_seconds:02d}")
        else:
            self.lockout_timer.stop()
            self.lockout_label.setText("Lockout expired. You can try again.")
            self.lockout_icon_label.setPixmap(QIcon.fromTheme("object-select", QIcon("icons/check-circle.svg")).pixmap(24, 24))
            self._set_login_form_enabled(True)

    def _set_login_form_enabled(self, enabled):
        """Disables or enables the login form widgets during lockout."""
        self.login_username_edit.setEnabled(enabled)
        self.login_password_edit.setEnabled(enabled)
        self.captcha_input_edit.setEnabled(enabled)
        self.login_button.setEnabled(enabled)
        self.theme_combo.setEnabled(enabled)
        self.links_widget.setVisible(enabled) # Hide register/forgot password links

    def _create_admin_login_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        admin_box = QGroupBox("Administrator Login")
        admin_box.setStyleSheet("QGroupBox { border: 1px solid #ccaa00; padding: 15px; }")
        form_layout = QFormLayout(admin_box)
        form_layout.setVerticalSpacing(15)

        self.admin_password_edit = QLineEdit()
        self.admin_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        # Admin Password field with toggle
        admin_password_container = QWidget()
        admin_password_layout = QHBoxLayout(admin_password_container)
        admin_password_layout.setContentsMargins(0,0,0,0)
        admin_password_layout.addWidget(self.admin_password_edit)
        admin_toggle_button = QPushButton()
        admin_toggle_button.setCheckable(True)
        admin_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        admin_toggle_button.setChecked(False)
        admin_toggle_button.setFixedSize(28, 28)
        admin_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        admin_toggle_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        def toggle_admin_password_visibility(checked):
            if checked:
                self.admin_password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                admin_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye.svg')))
            else:
                self.admin_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
                admin_toggle_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), 'icons', 'eye-off.svg')))
        admin_toggle_button.toggled.connect(toggle_admin_password_visibility)
        admin_password_layout.addWidget(admin_toggle_button)
        form_layout.addRow("Admin Password:", admin_password_container)

        admin_login_btn = QPushButton("Login as Admin")
        admin_login_btn.clicked.connect(self._handle_admin_login)
        form_layout.addRow(admin_login_btn)

        layout.addWidget(admin_box)
        return page

    def _handle_admin_login(self):
        """Dedicated login handler for the admin override form."""
        password = self.admin_password_edit.text()
        if not password:
            QMessageBox.warning(self, "Input Error", "Password is required.")
            return

        # We directly call verify_user for 'admin'
        user = database.verify_user('admin', password)
        if user:
            self.current_user = dict(user)
            QMessageBox.information(self, "Success", "Welcome, Administrator!")
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid admin password.")

    def _handle_login(self):
        username = self.login_username_edit.text().strip()
        password = self.login_password_edit.text()
        login_method = self.login_method_combo.currentText()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Username and password are required.")
            return

        # Always check for an existing lockout first.
        # We pass a dummy password because we only want to check the user's status.
        user_or_status = database.verify_user(username, "dummypass_for_status_check", is_status_check=True)
        if isinstance(user_or_status, str) and user_or_status.startswith('locked:'):
            self._handle_lockout_message(user_or_status)
            return

        # --- Main Login Logic ---
        # Now, verify the actual password provided by the user.
        user_data = database.verify_user(username, password)

        if not user_data:
            # This handles incorrect password and also registers the failed attempt,
            # which might trigger a lockout.
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")
            # We must re-check the status in case this failure caused a lockout.
            status_after_fail = database.verify_user(username, "dummypass_for_status_check", is_status_check=True)
            if isinstance(status_after_fail, str) and status_after_fail.startswith('locked:'):
                self._handle_lockout_message(status_after_fail)
            return

        # --- Method-Specific Validation ---
        if login_method == "Captcha":
            captcha_input = self.captcha_input_edit.text().strip()
            if not captcha_input or (captcha_input.upper() != self.captcha_text.upper()):
                QMessageBox.warning(self, "Login Failed", "Incorrect captcha. Please try again.")
                database.register_failed_login_attempt(username) # Registering a failed attempt for wrong captcha
                self._refresh_captcha('login')
                self.captcha_input_edit.clear()
                return

        elif login_method == "OTP":
            otp_code = self.login_otp_edit.text().strip()
            # Check for key existence before accessing sqlite3.Row object
            if 'otp_secret' not in user_data.keys() or not user_data['otp_secret']:
                QMessageBox.warning(self, "Login Failed", "OTP (2FA) is not enabled for this account.")
                return
            if not otp_code:
                QMessageBox.warning(self, "Input Error", "The OTP field is required for this login method.")
                return

            totp = pyotp.TOTP(user_data['otp_secret'])
            if not totp.verify(otp_code):
                QMessageBox.warning(self, "Login Failed", "Invalid One-Time Password.")
                database.register_failed_login_attempt(username) # Registering a failed attempt for wrong OTP
                return

        # --- Success ---
        # If we've reached this point, all checks have passed.
        self.current_user = dict(user_data)

        # Check for default password
        if password == "P@ssw0rd1234567890":
            force_change_dialog = ForcePasswordChangeDialog(self.current_user['id'], self)
            if force_change_dialog.exec() == QDialog.DialogCode.Accepted:
                # After successful password change, ask about 2FA
                reply = QMessageBox.question(self, "Enable Two-Factor Authentication?",
                                             "Your password has been updated. Would you like to enable Two-Factor Authentication (2FA) for enhanced security?",
                                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                             QMessageBox.StandardButton.Yes)
                if reply == QMessageBox.StandardButton.Yes:
                    otp_setup_dialog = OTPSetupDialog(self.current_user['id'], self.current_user['email'], self)
                    otp_setup_dialog.exec() # User can cancel this, it's optional
            else:
                # This case should not happen if the dialog cannot be closed, but as a fallback:
                QMessageBox.critical(self, "Login Aborted", "You must change your password to continue.")
                self.current_user = None # Abort login
                return

        # Log the successful login event before showing the final message
        database.log_activity(
            user_id=self.current_user['id'],
            category='Authentication',
            action='User Login',
            target=self.current_user['username'],
            details=f"Login method used: {login_method}"
        )
        QMessageBox.information(self, "Success", f"Welcome, {self.current_user['username']}!")
        self.accept()

    def _handle_register(self):
        username = self.reg_username_edit.text().strip()
        email = self.reg_email_edit.text().strip()
        password = self.reg_password_edit.text()
        confirm_password = self.reg_confirm_password_edit.text()
        captcha_input = self.reg_captcha_input_edit.text().strip()

        # --- Validation ---
        if not all([username, email, password, confirm_password, captcha_input]):
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            QMessageBox.warning(self, "Input Error", "Please enter a valid email address.")
            return

        if captcha_input.upper() != self.reg_captcha_text.upper():
            QMessageBox.warning(self, "Input Error", "Incorrect captcha. Please try again.")
            self._refresh_captcha('register')
            return

        if not self.tos_checkbox.isChecked():
            QMessageBox.warning(self, "Input Error", "You must accept the Terms of Service to register.")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
            return

        # Check password strength requirements before proceeding
        if not (len(password) >= 6 and any(c.isdigit() for c in password) and any(c in r"!@#$%^&*()_+-=[]{}|;':,./<>?" for c in password)):
            QMessageBox.warning(self, "Password Too Weak", "Your password does not meet the complexity requirements.\nPlease ensure it has at least 6 characters, one number, and one special character.")
            return

        if database.check_username_or_email_exists(username, email):
            QMessageBox.warning(self, "Input Error", "Username or email already exists.")
            return

        # Security questions validation
        questions_with_answers = []
        selected_question_ids = set()
        for item in self.security_questions_widgets:
            q_id = item['combo'].currentData()
            answer = item['answer'].text().strip()
            if not answer:
                QMessageBox.warning(self, "Input Error", "All three security questions must be answered.")
                return
            if q_id in selected_question_ids:
                QMessageBox.warning(self, "Input Error", "Please select three different security questions.")
                return
            selected_question_ids.add(q_id)
            questions_with_answers.append((q_id, answer))

        # --- Database Interaction ---
        try:
            user_id = database.create_user(username, email, password)
            database.add_security_questions(user_id, questions_with_answers)

            if self.enable_otp_checkbox.isChecked():
                # Show OTP setup and verification dialog
                # This needs to be a blocking dialog that handles its own logic
                otp_setup_dialog = OTPSetupDialog(user_id, email, self)
                if otp_setup_dialog.exec() == QDialog.DialogCode.Accepted:
                    QMessageBox.information(self, "Success", "Account and 2FA created successfully! Please log in.")
                else:
                    # User cancelled OTP setup. Inform them it's not enabled.
                    QMessageBox.warning(self, "Account Created", "Account was created, but 2FA was not enabled because the setup was cancelled.")
            else:
                 QMessageBox.information(self, "Success", "Account created successfully! Please log in.")

            self.stacked_widget.setCurrentWidget(self.login_page_stack) # Go back to the login view
        except Exception as e:
            logging.error(f"Error during registration: {e}", exc_info=True)
            QMessageBox.critical(self, "Database Error", "An error occurred during registration. Please try again later.")

    def closeEvent(self, event):
        if not self.current_user:
            sys.exit(0)
        event.accept()

class OTPSetupDialog(QDialog):
    """
    A dialog for setting up and verifying OTP for the first time during registration.
    """
    def __init__(self, user_id, user_email, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.user_email = user_email
        self.otp_secret = pyotp.random_base32()

        self.setWindowTitle("Enable Two-Factor Authentication")
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        layout.addWidget(QLabel("<b>Step 1: Scan the QR Code</b>"))
        layout.addWidget(QLabel("Scan the image below with your authenticator app (e.g., Google Authenticator)."))

        # Generate and display QR code
        qr_label = QLabel()
        otp_uri = pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.user_email,
            issuer_name="Zurvan App"
        )
        qr_img = qrcode.make(otp_uri)
        img_byte_array = io.BytesIO()
        qr_img.save(img_byte_array, format='PNG')
        pixmap = QPixmap()
        pixmap.loadFromData(img_byte_array.getvalue())
        qr_label.setPixmap(pixmap)
        layout.addWidget(qr_label, 0, Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(QLabel(f"Or manually enter this secret: {self.otp_secret}"))

        layout.addWidget(QLabel("<b>Step 2: Verify Your Code</b>"))
        layout.addWidget(QLabel("To confirm setup, enter the 6-digit code from your app below."))

        self.verify_input = QLineEdit()
        self.verify_input.setPlaceholderText("Enter 6-digit code")
        layout.addWidget(self.verify_input)

        self.verify_button = QPushButton("Verify and Enable 2FA")
        self.verify_button.clicked.connect(self._verify_and_save)
        layout.addWidget(self.verify_button)

    def _verify_and_save(self):
        entered_code = self.verify_input.text().strip()
        if not entered_code.isdigit() or len(entered_code) != 6:
            QMessageBox.warning(self, "Invalid Code", "Please enter a valid 6-digit code from your authenticator app.")
            return

        totp = pyotp.TOTP(self.otp_secret)
        if totp.verify(entered_code):
            try:
                database.set_otp_secret(self.user_id, self.otp_secret)
                self.accept() # Signal success
            except Exception as e:
                logging.error(f"Error saving OTP secret: {e}", exc_info=True)
                QMessageBox.critical(self, "Database Error", "Could not save OTP secret. Please try again later.")
                self.reject() # Signal failure
        else:
            QMessageBox.warning(self, "Verification Failed", "The code is incorrect. Please try again.")

    def closeEvent(self, event):
        """Override close event to ensure user understands OTP is not enabled if they close the dialog."""
        reply = QMessageBox.question(self, "Cancel Setup?",
                                     "If you close this window, 2FA will not be enabled for your account. Are you sure you want to cancel?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            event.accept() # This will cause exec() to return Rejected
        else:
            event.ignore()

if __name__ == '__main__':
    # This is a minimal example for testing the dialog directly
    from theme_support import apply_stylesheet
    app = QApplication(sys.argv)

    # You might need to create a dummy database for direct testing
    if not os.path.exists(database.DATABASE_NAME):
        database.initialize_database()

    # Apply a theme to see the effect
    apply_stylesheet(app, theme='dark_blue.xml')

    dialog = LoginDialog()
    if dialog.exec() == QDialog.DialogCode.Accepted:
        print(f"Login successful for user: {dialog.current_user['username']}")
    else:
        print("Login dialog closed or failed.")
