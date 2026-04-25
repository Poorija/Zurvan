from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTabWidget
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QGraphicsOpacityEffect
import sys

app = QApplication(sys.argv)

window = QWidget()
layout = QVBoxLayout(window)
tab_widget = QTabWidget()

tab1 = QWidget()
tab_widget.addTab(tab1, "Tab 1")

tab2 = QWidget()
tab_widget.addTab(tab2, "Tab 2")

layout.addWidget(tab_widget)
window.show()

def on_tab_changed(index):
    try:
        current_widget = tab_widget.widget(index)
        if current_widget:
            opacity_effect = QGraphicsOpacityEffect(current_widget)
            current_widget.setGraphicsEffect(opacity_effect)
            animation = QPropertyAnimation(opacity_effect, b"opacity")
            animation.setDuration(300)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
            animation.start()
            print(f"Animation started on tab {index}")
    except Exception as e:
        print(f"Error animating tab: {e}")

tab_widget.currentChanged.connect(on_tab_changed)

on_tab_changed(0)

QTimer = __import__('PyQt6.QtCore').QtCore.QTimer
QTimer.singleShot(1000, lambda: tab_widget.setCurrentIndex(1))
QTimer.singleShot(2000, app.quit)

sys.exit(app.exec())
