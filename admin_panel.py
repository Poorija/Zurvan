from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton, QHBoxLayout,
    QMessageBox, QInputDialog, QHeaderView, QGroupBox, QFormLayout, QLineEdit,
    QSplitter, QWidget, QComboBox, QLabel
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
        self.history_tab = QWidget()
        self.tabs.addTab(self.user_management_tab, "User Management")
        self.tabs.addTab(self.history_tab, "Test History")

        # Populate Tabs
        self._create_user_management_widgets()
        self._create_history_widgets()

        self._populate_users()
        self._populate_admin_history_tab()

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
        self.toggle_active_btn = QPushButton("Enable/Disable User")
        self.reset_password_btn = QPushButton("Reset User Password")
        actions_layout.addWidget(self.toggle_active_btn)
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

        main_splitter.addWidget(bottom_pane)
        main_splitter.setSizes([400, 200]) # Initial size ratio
        tab_layout.addWidget(main_splitter)

        # --- Bottom-most refresh button ---
        self.refresh_btn = QPushButton("Refresh User List")
        tab_layout.addWidget(self.refresh_btn)

        # --- Connect signals ---
        self.toggle_active_btn.clicked.connect(self._toggle_user_active_status)
        self.reset_password_btn.clicked.connect(self._reset_user_password)
        self.save_profile_btn.clicked.connect(self._save_profile)
        self.refresh_btn.clicked.connect(self._populate_users)

        # Initially disable editing widgets
        self._set_editing_widgets_enabled(False)

    def _create_history_widgets(self):
        """Creates the widgets for the test history tab."""
        tab_layout = QVBoxLayout(self.history_tab)

        # --- Controls ---
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Filter by User:"))
        self.history_user_filter_combo = QComboBox()
        self.history_user_filter_combo.currentTextChanged.connect(self._populate_admin_history_tab)
        controls_layout.addWidget(self.history_user_filter_combo)

        self.history_refresh_btn = QPushButton("Refresh")
        self.history_refresh_btn.clicked.connect(self._populate_admin_history_tab)
        controls_layout.addWidget(self.history_refresh_btn)
        controls_layout.addStretch()
        self.history_delete_btn = QPushButton("Delete Selected Entry")
        self.history_delete_btn.clicked.connect(self._delete_history_entry)
        controls_layout.addWidget(self.history_delete_btn)
        tab_layout.addLayout(controls_layout)

        # --- History Tree ---
        self.admin_history_tree = QTreeWidget()
        self.admin_history_tree.setColumnCount(5)
        self.admin_history_tree.setHeaderLabels(["Timestamp", "Username", "Test Type", "Target", "Result Summary"])
        self.admin_history_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.admin_history_tree.header().setStretchLastSection(True)
        self.admin_history_tree.header().resizeSection(0, 180)
        self.admin_history_tree.header().resizeSection(1, 120)
        tab_layout.addWidget(self.admin_history_tree)


    def _populate_admin_history_tab(self):
        """Fetches and displays test history, optionally filtered by user."""
        # This can be called before the widget is created when the dialog opens
        if not hasattr(self, 'admin_history_tree'):
            return

        self.admin_history_tree.clear()

        # Populate user filter combo box, preserving the current selection
        current_selection = self.history_user_filter_combo.currentText()
        self.history_user_filter_combo.blockSignals(True)
        self.history_user_filter_combo.clear()
        self.history_user_filter_combo.addItem("All Users")
        users = database.get_all_users()
        for user in users:
            self.history_user_filter_combo.addItem(user['username'], userData=user['id'])
        self.history_user_filter_combo.setCurrentText(current_selection)
        self.history_user_filter_combo.blockSignals(False)

        user_id_filter = self.history_user_filter_combo.currentData()

        try:
            history_records = database.get_test_history(user_id=user_id_filter)
            for record in history_records:
                summary = (record['results'] or "").split('\n')[0]
                summary = (summary[:100] + '...') if len(summary) > 100 else summary
                item = QTreeWidgetItem([
                    record['timestamp'],
                    record['username'],
                    record['test_type'],
                    record['target'],
                    summary
                ])
                item.setData(0, Qt.ItemDataRole.UserRole, record['id']) # Store history ID
                self.admin_history_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "History Error", f"Could not load test history: {e}")

    def _delete_history_entry(self):
        """Deletes the selected entry from the history table."""
        selected_items = self.admin_history_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a history entry to delete.")
            return

        history_id = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(self, "Confirm Deletion",
                                     f"Are you sure you want to permanently delete this history entry (ID: {history_id})?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.delete_history_entry(history_id)
                QMessageBox.information(self, "Success", "History entry deleted.")
                self._populate_admin_history_tab() # Refresh the view
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete history entry: {e}")

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
        self.reset_password_btn.setEnabled(enabled)
        self.username_edit.setEnabled(enabled)
        self.email_edit.setEnabled(enabled)
        self.full_name_edit.setEnabled(enabled)
        self.age_edit.setEnabled(enabled)
        self.job_title_edit.setEnabled(enabled)
        self.save_profile_btn.setEnabled(enabled)

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
        self.username_edit.setEnabled(not is_admin_user)

        self.full_name_edit.setText(profile_data.get("full_name") or "")
        age = profile_data.get("age")
        self.age_edit.setText(str(age) if age is not None else "")
        self.job_title_edit.setCurrentText(profile_data.get("job_title") or "")

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

            QMessageBox.information(self, "Success", "User profile updated successfully.")
            self._populate_users() # Refresh list to show new data

        except sqlite3.IntegrityError as e:
             QMessageBox.critical(self, "Database Error", f"Failed to update profile: Username or email already exists.\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update profile: {e}")

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

        reply = QMessageBox.question(self, "Confirm Action", f"Are you sure you want to {action_text} the user '{username}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.set_user_active_status(user_id, new_status)
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
                QMessageBox.information(self, "Success", f"Password for '{username}' has been reset.")
            except Exception as e:
                 QMessageBox.critical(self, "Database Error", f"Failed to reset password: {e}")
        else:
            QMessageBox.information(self, "Cancelled", "Password reset was cancelled.")
