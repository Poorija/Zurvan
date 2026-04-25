## 2025-05-18 - Exception Leakage in PyQt6 UI
**Vulnerability:** Raw Python exceptions were displayed to the user via QMessageBox.
**Learning:** PyQt6 applications often catch exceptions at the top level and naively display them to the user, leading to information leakage.
**Prevention:** Catch specific exceptions, log them with exc_info=True, and show generic messages to users.
