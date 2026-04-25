import sqlite3
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton, QHBoxLayout,
    QMessageBox, QInputDialog, QHeaderView, QGroupBox, QFormLayout, QLineEdit,
    QSplitter, QWidget, QComboBox, QLabel, QTabWidget, QGridLayout
)
from PyQt6.QtCore import Qt
import database

class AdminPanelDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Panel")
        self.setMinimumSize(800, 600)
        self.main_layout = QVBoxLayout(self)

        # Create Tabbed Interface
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        # Create Tabs
        self.user_management_tab = QWidget()
        self.activity_journal_tab = QWidget()
        self.tabs.addTab(self.user_management_tab, "User Management")
        self.login_history_tab = QWidget()
        self.tabs.addTab(self.login_history_tab, "Login History")
        self.tabs.addTab(self.activity_journal_tab, "Activity Journal")
        # Connect the tab change signal to the population methods
        self.tabs.currentChanged.connect(self._on_tab_changed)


        # Populate Tabs
        self._create_user_management_widgets()
        self._create_login_history_widgets()
        self._create_activity_journal_widgets() # Renamed method

        self._populate_users()
        self._populate_login_history_tab()
        self._populate_activity_journal_tab() # Renamed method

    def _on_tab_changed(self, index):
        """Populates the selected tab with data when it becomes visible."""
        tab_text = self.tabs.tabText(index)
        if tab_text == "Login History":
            self._populate_login_history_tab()
        elif tab_text == "Activity Journal":
            self._populate_activity_journal_tab()
        elif tab_text == "User Management":
            self._populate_users()


    def _create_user_management_widgets(self):
        """Creates the widgets for the user management tab."""
        tab_layout = QVBoxLayout(self.user_management_tab)
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # --- Top Pane: User List ---
        self.user_tree = QTreeWidget()
        self.user_tree.setColumnCount(5)
        self.user_tree.setHeaderLabels(["ID", "Username", "Email", "Is Admin?", "Is Active?"])
        self.user_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.user_tree.currentItemChanged.connect(self._on_user_selected)
        main_splitter.addWidget(self.user_tree)

        # --- Bottom Pane: Editing Controls ---
        bottom_pane = QWidget()
        bottom_layout = QHBoxLayout(bottom_pane)

        # Left side: Actions
        actions_box = QGroupBox("User Actions")
        actions_layout = QVBoxLayout(actions_box)
        self.add_user_btn = QPushButton("Add New User")
        self.delete_user_btn = QPushButton("Delete Selected User")
        self.toggle_active_btn = QPushButton("Enable/Disable User")
        self.toggle_admin_btn = QPushButton("Grant/Revoke Admin")
        self.reset_password_btn = QPushButton("Reset User Password")
        actions_layout.addWidget(self.add_user_btn)
        actions_layout.addWidget(self.delete_user_btn)
        actions_layout.addSpacing(10) # Visual separator
        actions_layout.addWidget(self.toggle_active_btn)
        actions_layout.addWidget(self.toggle_admin_btn)
        actions_layout.addWidget(self.reset_password_btn)
        actions_layout.addStretch()
        bottom_layout.addWidget(actions_box)

        # Right side: Profile Editing
        profile_box = QGroupBox("Edit User Profile")
        profile_form = QFormLayout(profile_box)
        self.username_edit = QLineEdit()
        self.email_edit = QLineEdit()
        self.full_name_edit = QLineEdit()
        self.age_edit = QLineEdit()

        self.job_title_edit = QComboBox()
        self.job_title_edit.addItems(["Red Team", "Blue Team", "Purple Team", "IT Team", "Network Team", "Manager", "Other"])
        self.job_title_edit.setEditable(True)

        self.save_profile_btn = QPushButton("Save Profile Changes")
        profile_form.addRow("Username:", self.username_edit)
        profile_form.addRow("Email:", self.email_edit)
        profile_form.addRow("Full Name:", self.full_name_edit)
        profile_form.addRow("Age:", self.age_edit)
        profile_form.addRow("Job Title:", self.job_title_edit)
        profile_form.addRow(self.save_profile_btn)
        bottom_layout.addWidget(profile_box, 1) # Give it more stretch

        # App Lock settings box
        app_lock_box = QGroupBox("App Lock Settings")
        app_lock_form = QFormLayout(app_lock_box)

        self.admin_app_lock_timeout_combo = QComboBox()
        timeouts = {"5 Minutes": 5, "15 Minutes": 15, "30 Minutes": 30, "1 Hour": 60, "Disabled": 0}
        for text, minutes in timeouts.items():
            self.admin_app_lock_timeout_combo.addItem(text, userData=minutes)

        self.admin_app_unlock_method_combo = QComboBox()
        self.admin_app_unlock_method_combo.addItems(["password", "pin"])

        self.admin_reset_pin_btn = QPushButton("Reset User PIN")

        app_lock_form.addRow("Auto-lock Timeout:", self.admin_app_lock_timeout_combo)
        app_lock_form.addRow("Unlock Method:", self.admin_app_unlock_method_combo)
        app_lock_form.addRow(self.admin_reset_pin_btn)
        bottom_layout.addWidget(app_lock_box)


        main_splitter.addWidget(bottom_pane)
        main_splitter.setSizes([400, 200]) # Initial size ratio
        tab_layout.addWidget(main_splitter)

        # --- Bottom-most refresh button ---
        self.refresh_btn = QPushButton("Refresh User List")
        tab_layout.addWidget(self.refresh_btn)

        # --- Connect signals ---
        self.toggle_active_btn.clicked.connect(self._toggle_user_active_status)
        self.toggle_admin_btn.clicked.connect(self._toggle_admin_status)
        self.add_user_btn.clicked.connect(self._add_user)
        self.delete_user_btn.clicked.connect(self._delete_user)
        self.toggle_active_btn.clicked.connect(self._toggle_user_active_status)
        self.toggle_admin_btn.clicked.connect(self._toggle_admin_status)
        self.reset_password_btn.clicked.connect(self._reset_user_password)
        self.save_profile_btn.clicked.connect(self._save_profile)
        self.refresh_btn.clicked.connect(self._populate_users)
        self.admin_app_lock_timeout_combo.currentIndexChanged.connect(self._handle_admin_save_lock_settings)
        self.admin_app_unlock_method_combo.currentIndexChanged.connect(self._handle_admin_save_lock_settings)
        self.admin_reset_pin_btn.clicked.connect(self._handle_admin_reset_pin)

        # Initially disable editing widgets
        self._set_editing_widgets_enabled(False)

    def _add_user(self):
        """Handles the logic for adding a new user."""
        username, ok1 = QInputDialog.getText(self, "Add User", "Enter username:")
        if not ok1 or not username:
            return

        email, ok2 = QInputDialog.getText(self, "Add User", f"Enter email for {username}:")
        if not ok2 or not email:
            return

        # Use the same default password as the admin user
        default_password = "P@ssw0rd1234567890"

        try:
            if database.check_username_or_email_exists(username, email):
                QMessageBox.warning(self, "Creation Failed", "A user with that username or email already exists.")
                return

            database.create_user(username, email, default_password)
            QMessageBox.information(self, "Success", f"User '{username}' created with the default password.\nThey will be required to change it on their first login.")
            self._populate_users() # Refresh the list

            # Log the admin action
            if self.parent() and self.parent().current_user:
                database.log_activity(
                    user_id=self.parent().current_user['id'],
                    category='Admin Action',
                    action='Created User',
                    details=f"Created new user: {username} ({email})",
                    severity='High',
                    result='Success'
                )

        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to create user: {e}")

    def _delete_user(self):
        """Handles the logic for deleting a selected user."""
        user_id = self._get_selected_user_id()
        if user_id is None:
            return

        username = self.user_tree.selectedItems()[0].text(1)
        if username == 'admin':
            QMessageBox.warning(self, "Action Denied", "The default admin account cannot be deleted.")
            return

        reply = QMessageBox.question(self, "Confirm Deletion",
                                     f"Are you sure you want to permanently delete the user '{username}'?\nThis action cannot be undone.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.delete_user(user_id)
                QMessageBox.information(self, "Success", f"User '{username}' has been deleted.")
                self._populate_users() # Refresh list

                # Log the admin action
                if self.parent() and self.parent().current_user:
                    database.log_activity(
                        user_id=self.parent().current_user['id'],
                        category='Admin Action',
                        action='Deleted User',
                        details=f"Deleted user: {username} (ID: {user_id})",
                        severity='Critical',
                        result='Success'
                    )

            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete user: {e}")

    def _create_login_history_widgets(self):
        """Creates the widgets for the login history tab."""
        tab_layout = QVBoxLayout(self.login_history_tab)

        # --- Controls ---
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Filter by User:"))
        self.login_history_user_filter_combo = QComboBox()
        self.login_history_user_filter_combo.currentTextChanged.connect(self._populate_login_history_tab)
        controls_layout.addWidget(self.login_history_user_filter_combo)

        self.login_history_refresh_btn = QPushButton("Refresh")
        self.login_history_refresh_btn.clicked.connect(self._populate_login_history_tab)
        controls_layout.addWidget(self.login_history_refresh_btn)
        controls_layout.addStretch()
        tab_layout.addLayout(controls_layout)

        # --- History Tree ---
        self.login_history_tree = QTreeWidget()
        self.login_history_tree.setColumnCount(3)
        self.login_history_tree.setHeaderLabels(["Timestamp", "Username", "Event"])
        self.login_history_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.login_history_tree.header().setStretchLastSection(True)
        self.login_history_tree.header().resizeSection(0, 180)
        self.login_history_tree.header().resizeSection(1, 150)
        tab_layout.addWidget(self.login_history_tree)

    def _create_activity_journal_widgets(self):
        """Creates the widgets for the activity journal tab."""
        tab_layout = QVBoxLayout(self.activity_journal_tab)

        # --- Controls ---
        controls_box = QGroupBox("Filters & Info")
        controls_grid = QGridLayout(controls_box)

        controls_grid.addWidget(QLabel("Filter by User:"), 0, 0)
        self.activity_user_filter_combo = QComboBox()
        self.activity_user_filter_combo.currentIndexChanged.connect(self._populate_activity_journal_tab)
        controls_grid.addWidget(self.activity_user_filter_combo, 0, 1)

        self.activity_refresh_btn = QPushButton("Refresh")
        self.activity_refresh_btn.clicked.connect(self._populate_activity_journal_tab)
        controls_grid.addWidget(self.activity_refresh_btn, 0, 2)

        self.activity_delete_btn = QPushButton("Delete Selected Entry")
        self.activity_delete_btn.clicked.connect(self._delete_history_entry)
        controls_grid.addWidget(self.activity_delete_btn, 0, 3)

        # --- Session Info ---
        controls_grid.addWidget(QLabel("<b>Last Visit:</b>"), 1, 0)
        self.session_last_visit_label = QLabel("N/A")
        controls_grid.addWidget(self.session_last_visit_label, 1, 1)

        controls_grid.addWidget(QLabel("<b>Total Session Duration:</b>"), 1, 2)
        self.session_duration_label = QLabel("N/A")
        controls_grid.addWidget(self.session_duration_label, 1, 3)

        tab_layout.addWidget(controls_box)


        # --- History Tree ---
        self.admin_activity_tree = QTreeWidget()
        self.admin_activity_tree.setColumnCount(8)
        self.admin_activity_tree.setHeaderLabels(["Timestamp", "User", "Category", "Action", "Severity", "Result", "Target", "Details"])
        self.admin_activity_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.admin_activity_tree.header().setStretchLastSection(True)
        self.admin_activity_tree.header().resizeSection(0, 160); self.admin_activity_tree.header().resizeSection(1, 100);
        self.admin_activity_tree.header().resizeSection(2, 120); self.admin_activity_tree.header().resizeSection(3, 150);
        self.admin_activity_tree.header().resizeSection(4, 80); self.admin_activity_tree.header().resizeSection(5, 80);
        self.admin_activity_tree.header().resizeSection(6, 150)
        tab_layout.addWidget(self.admin_activity_tree)

    def _populate_user_filter_combo(self, combo_box, add_user_data=False):
        """Helper function to populate a user filter combo box."""
        current_selection = combo_box.currentText()
        combo_box.blockSignals(True)
        combo_box.clear()
        combo_box.addItem("All Users", userData=None)
        users = database.get_all_users()
        for user in users:
            if add_user_data:
                combo_box.addItem(user['username'], userData=user['id'])
            else:
                combo_box.addItem(user['username'])
        combo_box.setCurrentText(current_selection)
        combo_box.blockSignals(False)

    def _populate_login_history_tab(self):
        """Fetches and displays login history, optionally filtered by user."""
        if not hasattr(self, 'login_history_tree'):
            return

        self.login_history_tree.clear()
        self._populate_user_filter_combo(self.login_history_user_filter_combo)

        username_filter = self.login_history_user_filter_combo.currentText()
        if username_filter == "All Users":
            username_filter = None

        try:
            history_records = database.get_login_history(username_filter=username_filter)
            for record in history_records:
                item = QTreeWidgetItem([
                    record['ts'],
                    record['username'],
                    record['event_type']
                ])
                self.login_history_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "History Error", f"Could not load login history: {e}")


    def _populate_activity_journal_tab(self):
        """Fetches and displays activity log and session info, optionally filtered by user."""
        if not hasattr(self, 'admin_activity_tree'):
            return

        self.admin_activity_tree.clear()
        self._populate_user_filter_combo(self.activity_user_filter_combo, add_user_data=True)

        user_id_filter = self.activity_user_filter_combo.currentData()

        # --- Update Session Info ---
        if user_id_filter is not None:
            session_info = database.get_user_session_info(user_id_filter)
            self.session_last_visit_label.setText(session_info.get('last_login', 'N/A'))
            self.session_duration_label.setText(session_info.get('total_duration_str', 'N/A'))
        else:
            self.session_last_visit_label.setText("Select a user")
            self.session_duration_label.setText("Select a user")

        # --- Populate Activity Log ---
        try:
            log_entries = database.get_activity_log(user_id=user_id_filter)
            for record in log_entries:
                item = QTreeWidgetItem([
                    str(record['timestamp']),
                    str(record['username']),
                    str(record['category']),
                    str(record['action']),
                    str(record['severity']),
                    str(record['result']),
                    str(record['target']),
                    str(record['details'])
                ])
                item.setData(0, Qt.ItemDataRole.UserRole, record['id']) # Store log ID
                self.admin_activity_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "History Error", f"Could not load activity journal: {e}")

    def _delete_history_entry(self):
        """Deletes the selected entry from the history table."""
        selected_items = self.admin_activity_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a log entry to delete.")
            return

        history_id = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(self, "Confirm Deletion",
                                     f"Are you sure you want to permanently delete this log entry (ID: {history_id})?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.delete_history_entry(history_id)
                if self.parent() and self.parent().current_user:
                    details = f"Admin deleted activity log entry with ID: {history_id}."
                    database.log_activity(
                        user_id=self.parent().current_user['id'],
                        category='Admin Action',
                        action='Deleted Activity Log',
                        details=details,
                        severity='High',
                        result='Success'
                    )
                QMessageBox.information(self, "Success", "Log entry deleted.")
                self._populate_activity_journal_tab() # Refresh the view
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete log entry: {e}")

    def _get_selected_user_id(self):
        """Helper to get the user ID from the selected item in the tree."""
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user from the list.")
            return None
        # User ID is in the first column (index 0)
        user_id = int(selected_items[0].text(0))
        return user_id

    def _set_editing_widgets_enabled(self, enabled):
        """Enables or disables all the user editing widgets."""
        self.toggle_active_btn.setEnabled(enabled)
        self.toggle_admin_btn.setEnabled(enabled)
        self.reset_password_btn.setEnabled(enabled)
        self.username_edit.setEnabled(enabled)
        self.email_edit.setEnabled(enabled)
        self.full_name_edit.setEnabled(enabled)
        self.age_edit.setEnabled(enabled)
        self.job_title_edit.setEnabled(enabled)
        self.save_profile_btn.setEnabled(enabled)
        self.admin_app_lock_timeout_combo.setEnabled(enabled)
        self.admin_app_unlock_method_combo.setEnabled(enabled)
        self.admin_reset_pin_btn.setEnabled(enabled)


    def _clear_profile_fields(self):
        """Clears the text from the profile editing fields."""
        self.username_edit.clear()
        self.email_edit.clear()
        self.full_name_edit.clear()
        self.age_edit.clear()
        self.job_title_edit.setCurrentIndex(-1)
        self.job_title_edit.clearEditText()

    def _populate_users(self):
        """Fetches all users from the database and populates the tree widget."""
        self.user_tree.clear()
        self._clear_profile_fields()
        self._set_editing_widgets_enabled(False)
        try:
            users = database.get_all_users()
            for user in users:
                item = QTreeWidgetItem([
                    str(user['id']),
                    user['username'],
                    user['email'],
                    "Yes" if user['is_admin'] else "No",
                    "Yes" if user['is_active'] else "No"
                ])
                # Store extra data in the item itself
                item.setData(0, Qt.ItemDataRole.UserRole, {
                    "full_name": user['full_name'],
                    "age": user['age'],
                    "job_title": user['job_title']
                })

                if not user['is_active']:
                    font = item.font(0)
                    font.setItalic(True)
                    for i in range(self.user_tree.columnCount()):
                        item.setFont(i, font)
                        item.setForeground(i, Qt.GlobalColor.gray)

                self.user_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load users: {e}")

    def _on_user_selected(self, current, previous):
        """Populates the editing fields when a user is selected."""
        if not current:
            self._clear_profile_fields()
            self._set_editing_widgets_enabled(False)
            return

        self._set_editing_widgets_enabled(True)
        profile_data = current.data(0, Qt.ItemDataRole.UserRole)
        username = current.text(1)
        email = current.text(2)

        self.username_edit.setText(username)
        self.email_edit.setText(email)

        # The default admin user cannot be disabled or have its username changed
        is_admin_user = (username == 'admin')
        self.toggle_active_btn.setEnabled(not is_admin_user)
        self.toggle_admin_btn.setEnabled(not is_admin_user)
        self.username_edit.setEnabled(not is_admin_user)

        self.full_name_edit.setText(profile_data.get("full_name") or "")
        age = profile_data.get("age")
        self.age_edit.setText(str(age) if age is not None else "")
        self.job_title_edit.setCurrentText(profile_data.get("job_title") or "")

        # Populate App Lock settings, blocking signals to prevent premature saves
        user_data = database.get_user_by_id(int(current.text(0)))
        self.admin_app_lock_timeout_combo.blockSignals(True)
        timeout = user_data.get('app_lock_timeout', 15)
        index = self.admin_app_lock_timeout_combo.findData(timeout)
        if index != -1:
            self.admin_app_lock_timeout_combo.setCurrentIndex(index)
        self.admin_app_lock_timeout_combo.blockSignals(False)

        self.admin_app_unlock_method_combo.blockSignals(True)
        method = user_data.get('app_unlock_method', 'password')
        self.admin_app_unlock_method_combo.setCurrentText(method)
        self.admin_app_unlock_method_combo.blockSignals(False)


    def _handle_admin_save_lock_settings(self):
        """Saves the app lock settings for the selected user from the admin panel."""
        user_id = self._get_selected_user_id()
        if user_id is None:
            return

        timeout = self.admin_app_lock_timeout_combo.currentData()
        method = self.admin_app_unlock_method_combo.currentText()

        try:
            database.update_user_app_lock_settings(user_id, timeout, method)
            if self.parent() and self.parent().current_user:
                username = self.user_tree.selectedItems()[0].text(1)
                details = f"Admin set lock timeout to {timeout} mins and method to '{method}' for {username} (ID: {user_id})."
                database.log_activity(
                    user_id=self.parent().current_user['id'],
                    category='Admin Action',
                    action='Updated Lock Settings',
                    details=details,
                    severity='Medium',
                    result='Success'
                )
            # No need for a popup, the change is instant. A status bar message could be added in the future.
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to update App Lock settings: {e}")

    def _handle_admin_reset_pin(self):
        """Resets the selected user's App Lock PIN."""
        user_id = self._get_selected_user_id()
        if user_id is None:
            return

        username = self.user_tree.selectedItems()[0].text(1)
        reply = QMessageBox.question(self, "Confirm PIN Reset",
                                     f"Are you sure you want to reset the App Lock PIN for '{username}'?\nThey will need to set a new one in their profile.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.clear_user_pin(user_id)
                if self.parent() and self.parent().current_user:
                    details = f"Admin reset App Lock PIN for user {username} (ID: {user_id})."
                    database.log_activity(
                        user_id=self.parent().current_user['id'],
                        category='Admin Action',
                        action='Reset PIN',
                        details=details,
                        severity='High',
                        result='Success'
                    )
                QMessageBox.information(self, "Success", f"PIN for '{username}' has been reset.")
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to reset PIN: {e}")


    def _save_profile(self):
        """Saves all changes from the profile fields to the database."""
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            return # Should not happen if button is enabled, but good practice

        user_id = int(selected_items[0].text(0))
        original_username = selected_items[0].text(1)
        original_email = selected_items[0].text(2)

        new_username = self.username_edit.text().strip()
        new_email = self.email_edit.text().strip()
        full_name = self.full_name_edit.text()
        age = self.age_edit.text()
        job_title = self.job_title_edit.currentText()

        try:
            # Update username if changed
            if new_username != original_username:
                # The 'update_user_username' function will need to handle checks for existence
                database.update_user_username(user_id, new_username)

            # Update email if changed
            if new_email != original_email:
                # The 'update_user_email' function will need to handle checks for existence
                database.update_user_email(user_id, new_email)

            # Update the rest of the profile info
            database.update_user_profile(user_id, full_name, age, job_title)

            # Log the admin action
            if self.parent() and self.parent().current_user:
                details = f"Admin updated profile for user ID {user_id} ({new_username})."
                database.log_activity(
                    user_id=self.parent().current_user['id'],
                    category='Admin Action',
                    action='Updated User Profile',
                    details=details,
                    severity='Medium',
                    result='Success'
                )

            QMessageBox.information(self, "Success", "User profile updated successfully.")
            self._populate_users() # Refresh list to show new data

        except sqlite3.IntegrityError as e:
             QMessageBox.critical(self, "Database Error", f"Failed to update profile: Username or email already exists.\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update profile: {e}")

    def _toggle_admin_status(self):
        """Grants or revokes admin privileges for the selected user."""
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user from the list.")
            return

        selected_item = selected_items[0]
        user_id = int(selected_item.text(0))
        username = selected_item.text(1)
        is_currently_admin = selected_item.text(3) == "Yes"

        if username == 'admin':
            QMessageBox.warning(self, "Action Denied", "The default admin account's status cannot be changed.")
            return

        new_status = not is_currently_admin
        action_text = "revoke admin privileges from" if is_currently_admin else "grant admin privileges to"
        log_action = "Revoked Admin" if is_currently_admin else "Granted Admin"

        reply = QMessageBox.question(self, "Confirm Action", f"Are you sure you want to {action_text} the user '{username}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.set_user_admin_status(user_id, new_status)
                if self.parent() and self.parent().current_user:
                    database.log_activity(
                        user_id=self.parent().current_user['id'],
                        category='Admin Action',
                        action=log_action,
                        details=f"User: {username} (ID: {user_id})",
                        severity='High',
                        result='Success'
                    )
                QMessageBox.information(self, "Success", f"Admin status for '{username}' has been updated.")
                self._populate_users() # Refresh list
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to update admin status: {e}")

    def _toggle_user_active_status(self):
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user from the list.")
            return

        selected_item = selected_items[0]
        user_id = int(selected_item.text(0))
        username = selected_item.text(1)
        is_currently_active = selected_item.text(4) == "Yes"

        if username == 'admin':
            QMessageBox.warning(self, "Action Denied", "The default admin account cannot be disabled.")
            return

        new_status = not is_currently_active
        action_text = "disable" if is_currently_active else "enable"
        log_action = "Deactivated User" if is_currently_active else "Activated User"


        reply = QMessageBox.question(self, "Confirm Action", f"Are you sure you want to {action_text} the user '{username}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.set_user_active_status(user_id, new_status)
                if self.parent() and self.parent().current_user:
                    database.log_activity(
                        user_id=self.parent().current_user['id'],
                        category='Admin Action',
                        action=log_action,
                        details=f"User: {username} (ID: {user_id})",
                        severity='Medium',
                        result='Success'
                    )
                QMessageBox.information(self, "Success", f"User '{username}' has been {action_text}d.")
                self._populate_users()
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to update user status: {e}")

    def _reset_user_password(self):
        user_id = self._get_selected_user_id()
        if user_id is None:
            return

        username = self.user_tree.selectedItems()[0].text(1)
        new_password, ok = QInputDialog.getText(self, "Reset Password", f"Enter new password for '{username}':", QLineEdit.EchoMode.Password)

        if ok and new_password:
            try:
                database.update_user_password(user_id, new_password)
                if self.parent() and self.parent().current_user:
                    database.log_activity(
                        user_id=self.parent().current_user['id'],
                        category='Admin Action',
                        action='Reset Password',
                        details=f"User: {username} (ID: {user_id})",
                        severity='High',
                        result='Success'
                    )
                QMessageBox.information(self, "Success", f"Password for '{username}' has been reset.")
            except Exception as e:
                 QMessageBox.critical(self, "Database Error", f"Failed to reset password: {e}")
        else:
            QMessageBox.information(self, "Cancelled", "Password reset was cancelled.")
