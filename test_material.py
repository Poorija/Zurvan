from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton
import sys
import qt_material

app = QApplication(sys.argv)

try:
    print(qt_material.build_stylesheet(theme='cyberpunk.xml')[:100])
except Exception as e:
    print("Failed to build:", e)
