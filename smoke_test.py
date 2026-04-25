#!/usr/bin/env python3
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox")

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

import database
from login import LoginDialog
from zurvan import Zurvan


def main():
    database.initialize_database()
    admin = database.verify_user("admin", "P@ssw0rd1234567890")
    if not admin:
        raise RuntimeError("Default admin credential check failed.")

    app = QApplication.instance() or QApplication(["zurvan-smoke"])

    login_dialog = LoginDialog()
    if login_dialog.windowTitle() == "":
        raise RuntimeError("Login dialog failed to initialize.")
    login_dialog.close()

    window = Zurvan()
    if window.tab_widget.count() < 5:
        raise RuntimeError("Main window tabs did not initialize correctly.")
    window.close()

    print(
        "Smoke checks passed: database, login dialog, and main window initialization.",
        flush=True,
    )
    QTimer.singleShot(0, app.quit)
    app.exec()


if __name__ == "__main__":
    main()
