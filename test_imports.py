import sys
from PyQt6.QtWidgets import QApplication
from zurvan import Zurvan

app = QApplication(sys.argv)
try:
    window = Zurvan()
    print("Zurvan loaded without NameError in initialization.")
except Exception as e:
    print(f"Error loading Zurvan: {e}")
