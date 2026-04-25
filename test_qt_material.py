from PyQt6.QtWidgets import QApplication, QPushButton
from qt_material import apply_stylesheet
import sys

app = QApplication(sys.argv)
apply_stylesheet(app, theme='cyberpunk.xml')
print("Applied successfully")
