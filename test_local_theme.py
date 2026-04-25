from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton
import qt_material
import sys

app = QApplication(sys.argv)
window = QWidget()
layout = QVBoxLayout(window)
layout.addWidget(QPushButton("Test Button"))
window.show()

try:
    qt_material.apply_stylesheet(app, theme='cyberpunk.xml')
    print("Theme applied.")
except Exception as e:
    print(f"Failed to apply: {e}")

QTimer = __import__('PyQt6.QtCore').QtCore.QTimer
QTimer.singleShot(500, app.quit)
app.exec()
