import sys
import random
import os
from PyQt6.QtWidgets import (
    QApplication, QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QStackedWidget, QFormLayout, QMessageBox, QGroupBox, QComboBox,
    QGraphicsOpacityEffect, QCheckBox
)
from qt_material import apply_stylesheet, list_themes
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer
from PyQt6.QtGui import QIcon, QPixmap
import database
import logging
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
        self.questions_layout.addRow(QLabel("Please answer your security questions:"))
        return page

    def _create_new_password_page(self):
        page = QWidget()
        layout = QFormLayout(page)
        self.new_pass_edit = QLineEdit()
        self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pass_edit = QLineEdit()
        self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("New Password:", self.new_pass_edit)
        layout.addRow("Confirm Password:", self.confirm_pass_edit)

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
            QMessageBox.critical(self, "Database Error", f"An unexpected error occurred while updating the password: {e}")


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("GScapy - Login")
        self.setModal(True)
        self.current_user = None
        self.selected_theme = 'dark_cyan.xml' # Default theme
        self.captcha_text = None

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
        icon_path = os.path.join(script_dir, "icons", "new_logo.png")
        pixmap = QPixmap(icon_path)
        self.logo_label.setPixmap(pixmap.scaled(80, 80, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        header_layout.addWidget(self.logo_label)

        # Text container
        text_widget = QWidget()
        text_layout = QVBoxLayout(text_widget)
        text_layout.setContentsMargins(0,0,0,0)
        text_layout.setSpacing(0)

        # App Name
        app_name_label = QLabel("GScapy + AI")
        app_name_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #bbbbbb;")
        app_name_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        text_layout.addWidget(app_name_label)

        # Slogan
        slogan_label = QLabel("The Modern Scapy Interface with AI")
        slogan_label.setStyleSheet("font-size: 14px; color: #888888;")
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

        self.lockout_end_time = None
        self.lockout_timer = QTimer(self)
        self.lockout_timer.timeout.connect(self._update_lockout_timer)

        self.setMinimumSize(500, 750) # Increased height for new widgets
        self.adjustSize()

        # --- Animation & Initial State ---
        self.start_logo_animation()
        self._refresh_captcha() # Load the first captcha

    def _handle_password_reset_request(self):
        """Opens the password reset dialog."""
        reset_dialog = PasswordResetDialog(self)
        reset_dialog.exec()

    def _handle_theme_change(self, theme_name):
        """Applies the selected theme to the entire application."""
        self.selected_theme = f"{theme_name}.xml"
        # This dictionary should be kept in sync with the one in gscapy.py
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

    def _refresh_captcha(self):
        """Generates a new captcha and updates the UI."""
        try:
            pixmap, text = generate_captcha()
            self.captcha_image_label.setPixmap(pixmap)
            self.captcha_text = text
        except Exception:
            self.captcha_image_label.setText("Captcha Failed")
            self.captcha_text = "fallback" # Set a fallback to prevent login lockout
            logging.error("Failed to generate captcha", exc_info=True)

    def _create_login_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        login_box = QGroupBox("User Login")
        login_box.setStyleSheet("QGroupBox { border: 1px solid #444; padding: 15px; }")

        self.login_form_layout = QFormLayout(login_box)

        # --- Lockout UI ---
        self.lockout_widget = QWidget()
        lockout_layout = QHBoxLayout(self.lockout_widget)
        self.lockout_icon_label = QLabel()
        self.lockout_icon_label.setPixmap(QIcon.fromTheme("dialog-error", QIcon("icons/new_logo.png")).pixmap(24, 24))
        self.lockout_label = QLabel()
        lockout_layout.addWidget(self.lockout_icon_label)
        lockout_layout.addWidget(self.lockout_label)
        self.lockout_widget.setVisible(False) # Hidden by default
        self.login_form_layout.addRow(self.lockout_widget)

        self.login_username_edit = QLineEdit()
        self.login_password_edit = QLineEdit()
        self.login_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_form_layout.addRow("Username:", self.login_username_edit)
        self.login_form_layout.addRow("Password:", self.login_password_edit)

        # --- Captcha ---
        self.captcha_image_label = QLabel("Captcha loading...")
        self.captcha_input_edit = QLineEdit()
        self.captcha_input_edit.setPlaceholderText("Enter Captcha Text")
        refresh_captcha_btn = QPushButton(" Regenerate")
        refresh_captcha_btn.setIcon(QIcon.fromTheme("view-refresh", QIcon("icons/refresh-cw.svg"))) # Use themed icon with fallback
        refresh_captcha_btn.clicked.connect(self._refresh_captcha)

        captcha_group_layout = QHBoxLayout()
        captcha_group_layout.addWidget(self.captcha_image_label, 2)
        captcha_group_layout.addWidget(self.captcha_input_edit, 2)
        captcha_group_layout.addWidget(refresh_captcha_btn, 1)
        self.login_form_layout.addRow("Captcha:", captcha_group_layout)

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

    def _create_register_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        register_box = QGroupBox("Create New Account")
        register_box.setStyleSheet("QGroupBox { border: 1px solid #444; padding: 15px; }")
        form_layout = QFormLayout(register_box)

        self.reg_username_edit = QLineEdit()
        self.reg_email_edit = QLineEdit()
        self.reg_password_edit = QLineEdit()
        self.reg_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm_password_edit = QLineEdit()
        self.reg_confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Username:", self.reg_username_edit)
        form_layout.addRow("Email:", self.reg_email_edit)
        form_layout.addRow("Password:", self.reg_password_edit)
        form_layout.addRow("Confirm Password:", self.reg_confirm_password_edit)

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

        self.admin_password_edit = QLineEdit()
        self.admin_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Admin Password:", self.admin_password_edit)

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
        captcha_input = self.captcha_input_edit.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Username and password are required.")
            return

        # Always check for existing lockout first
        user_or_status = database.verify_user(username, "dummypass_for_status_check")
        if isinstance(user_or_status, str) and user_or_status.startswith('locked:'):
            self._handle_lockout_message(user_or_status)
            return

        # Check captcha
        if not captcha_input or (captcha_input.upper() != self.captcha_text.upper()):
            QMessageBox.warning(self, "Login Failed", "Incorrect captcha. Please try again.")
            database.register_failed_login_attempt(username)
            self._refresh_captcha()
            self.captcha_input_edit.clear()
            # Check if this failed attempt caused a lockout
            user_or_status = database.verify_user(username, "dummypass_for_status_check")
            if isinstance(user_or_status, str) and user_or_status.startswith('locked:'):
                self._handle_lockout_message(user_or_status)
            return

        # If captcha is correct, proceed with real password verification
        user_or_status = database.verify_user(username, password)

        if user_or_status: # This will only be a user object on success
            self.current_user = dict(user_or_status)
            QMessageBox.information(self, "Success", f"Welcome, {self.current_user['username']}!")
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")
            self._refresh_captcha()
            self.captcha_input_edit.clear()
            # Check if this failed attempt caused a lockout
            user_or_status = database.verify_user(username, "dummypass_for_status_check")
            if isinstance(user_or_status, str) and user_or_status.startswith('locked:'):
                self._handle_lockout_message(user_or_status)

    def _handle_register(self):
        username = self.reg_username_edit.text().strip()
        email = self.reg_email_edit.text().strip()
        password = self.reg_password_edit.text()
        confirm_password = self.reg_confirm_password_edit.text()

        # --- Validation ---
        if not all([username, email, password, confirm_password]):
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return
        if password != confirm_password:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
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
            QMessageBox.information(self, "Success", "Account created successfully! Please log in.")
            self.stacked_widget.setCurrentWidget(self.login_page)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"An error occurred during registration: {e}")

    def closeEvent(self, event):
        if not self.current_user:
            sys.exit(0)
        event.accept()

if __name__ == '__main__':
    # This is a minimal example for testing the dialog directly
    from qt_material import apply_stylesheet
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
