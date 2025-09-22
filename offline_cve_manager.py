from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QLabel, QPushButton, QHBoxLayout
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import pyqtSignal

class OfflineCveManagerWidget(QWidget):
    """A reusable widget for managing the offline CVE database."""
    start_import = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent # The main Zurvan window

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        main_box = QGroupBox("Offline CVE Database Management")
        main_layout = QVBoxLayout(main_box)

        instructions = QLabel("Import NVD data feeds to build or update your local, offline CVE database. This database is used for the 'Aggregate & Enrich' feature in the Reporting tab.")
        instructions.setWordWrap(True)
        main_layout.addWidget(instructions)

        buttons_layout = QHBoxLayout()
        self.import_button = QPushButton(QIcon("icons/folder.svg"), " Import NVD File(s)")
        self.import_button.setToolTip("Select one or more NVD JSON feeds (*.json.gz) to import.")
        buttons_layout.addWidget(self.import_button)

        self.info_button = QPushButton(QIcon("icons/help-circle.svg"), " Manual Update Info")
        self.info_button.setToolTip("Show instructions for manually downloading the latest NVD data feeds.")
        buttons_layout.addWidget(self.info_button)
        buttons_layout.addStretch()
        main_layout.addLayout(buttons_layout)

        self.status_label = QLabel("Status: Idle")
        main_layout.addWidget(self.status_label)

        layout.addWidget(main_box)
        layout.addStretch()

        # Connections
        self.import_button.clicked.connect(self.start_import.emit)
        self.info_button.clicked.connect(self.parent._show_cve_update_info)

    def set_status(self, text):
        """Public method to update the status label."""
        self.status_label.setText(f"Status: {text}")

    def set_buttons_enabled(self, enabled):
        """Public method to enable/disable buttons during operation."""
        self.import_button.setEnabled(enabled)
        self.info_button.setEnabled(enabled)
