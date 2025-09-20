import logging
import json
import os
import re
import socket

from PyQt6.QtCore import (
    pyqtSignal, Qt, QTimer, QPoint, QSize, QPropertyAnimation, QEasingCurve,
    QParallelAnimationGroup, QSequentialAnimationGroup
)
from PyQt6.QtGui import QActionGroup, QAction, QPalette, QIcon, QImage, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGridLayout,
    QDialog, QTabWidget, QLineEdit, QPushButton, QComboBox, QMessageBox,
    QInputDialog, QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem,
    QFrame, QMenu, QTextEdit, QTextBrowser, QGroupBox, QLabel, QSplitter, QScrollArea,
    QSizePolicy
)

from ai_threads import FetchModelsThread, TestAPIThread, AIAnalysisThread

# This function is used by the AIAssistantTab and its components
def create_themed_icon(icon_path, color_str):
    """Loads an SVG, intelligently replaces its color, and returns a QIcon."""
    try:
        with open(icon_path, 'r', encoding='utf-8') as f:
            svg_data = f.read()

        # First, try to replace a stroke color in a style block (for paper-airplane.svg)
        themed_svg_data, count = re.subn(r'stroke:#[0-9a-fA-F]{6}', f'stroke:{color_str}', svg_data)

        # If no stroke was found in a style, fall back to injecting a fill attribute (for gear.svg)
        if count == 0 and '<svg' in themed_svg_data:
            themed_svg_data = themed_svg_data.replace('<svg', f'<svg fill="{color_str}"')

        image = QImage.fromData(themed_svg_data.encode('utf-8'))
        pixmap = QPixmap.fromImage(image)
        return QIcon(pixmap)
    except Exception as e:
        logging.warning(f"Could not create themed icon for {icon_path}: {e}")
        return QIcon(icon_path) # Fallback to original icon


class AISettingsDialog(QDialog):
    """A dialog to configure the AI analysis feature."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Analysis Settings")
        self.setMinimumWidth(500)
        self.settings_file = "ai_settings.json"
        self.fetch_thread = None

        # Main layout
        main_layout = QVBoxLayout(self)

        # Tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # --- Local AI Tab ---
        local_ai_widget = QWidget()
        local_ai_layout = QFormLayout(local_ai_widget)

        self.local_endpoint_edit = QLineEdit()
        detect_button = QPushButton("Detect Running Services")
        detect_button.clicked.connect(self.detect_local_services)
        local_ai_layout.addRow("API Endpoint URL:", self.local_endpoint_edit)
        local_ai_layout.addRow(detect_button)

        # Model selection with refresh
        model_layout = QHBoxLayout()
        self.local_model_combo = QComboBox()
        self.local_model_combo.setEditable(True)
        self.local_model_combo.setToolTip("Select an available model or type a custom one.")
        model_layout.addWidget(self.local_model_combo)
        self.refresh_button = QPushButton("Refresh List")
        self.refresh_button.clicked.connect(self.refresh_local_models)
        model_layout.addWidget(self.refresh_button)
        local_ai_layout.addRow("Model Name:", model_layout)

        self.tab_widget.addTab(local_ai_widget, "Local AI (Ollama, etc.)")

        # --- Online Services Tab ---
        online_ai_widget = QWidget()
        online_main_layout = QVBoxLayout(online_ai_widget)

        self.online_provider_tabs = QTabWidget()
        online_main_layout.addWidget(self.online_provider_tabs)

        # Create a dictionary to hold the widgets for each provider
        self.provider_widgets = {}

        # List of providers to add
        providers = ["OpenAI", "Gemini", "Grok", "DeepSeek", "Qwen"]

        for provider_name in providers:
            provider_widget = QWidget()
            provider_layout = QFormLayout(provider_widget)

            api_key_edit = QLineEdit()
            api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)

            model_edit = QLineEdit()

            test_button = QPushButton("Test Connection")

            # Enable the button only for implemented providers
            if provider_name == "OpenAI":
                test_button.setEnabled(True)
                test_button.clicked.connect(lambda checked, p=provider_name: self._test_api_connection(p))
            else:
                test_button.setEnabled(False)

            provider_layout.addRow(f"{provider_name} API Key:", api_key_edit)
            provider_layout.addRow("Model Name:", model_edit)
            provider_layout.addRow(test_button)

            self.provider_widgets[provider_name] = {
                'api_key': api_key_edit,
                'model': model_edit,
                'test_btn': test_button
            }
            self.online_provider_tabs.addTab(provider_widget, provider_name)

        self.tab_widget.addTab(online_ai_widget, "Online Services")

        # --- Save/Cancel Buttons ---
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        self.load_settings()

    def detect_local_services(self):
        """Tries to detect common local AI endpoints by checking for open ports."""
        known_services = {
            "Ollama": {"port": 11434, "path": "/api/chat"},
            "LMStudio": {"port": 1234, "path": "/v1/chat/completions"}
        }
        detected_services = []

        for name, details in known_services.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1) # Quick timeout
                    s.connect(("localhost", details["port"]))
                detected_services.append(name)
            except (socket.timeout, ConnectionRefusedError):
                continue

        if not detected_services:
            QMessageBox.information(self, "Detection Result", "No running local AI services (Ollama, LMStudio) could be detected on their default ports.")
        elif len(detected_services) == 1:
            service_name = detected_services[0]
            port = known_services[service_name]["port"]
            path = known_services[service_name]["path"]
            endpoint = f"http://localhost:{port}{path}"
            self.local_endpoint_edit.setText(endpoint)
            QMessageBox.information(self, "Detection Result", f"Detected {service_name} running. Endpoint has been set.\n\nPlease refresh the model list.")
        else: # Multiple services detected
            service_name, ok = QInputDialog.getItem(self, "Multiple Services Detected",
                                                    "Multiple AI services were found. Please select one to configure:",
                                                    detected_services, 0, False)
            if ok and service_name:
                port = known_services[service_name]["port"]
                path = known_services[service_name]["path"]
                endpoint = f"http://localhost:{port}{path}"
                self.local_endpoint_edit.setText(endpoint)

    def refresh_local_models(self):
        """Queries the local AI endpoint to get a list of available models."""
        endpoint = self.local_endpoint_edit.text()
        if not endpoint:
            QMessageBox.warning(self, "Error", "Please enter a local AI endpoint URL first.")
            return

        if endpoint.endswith("/api/chat"):
            tags_url = endpoint.replace("/api/chat", "/api/tags")
        else:
            QMessageBox.information(self, "Unsupported", "Model auto-discovery is currently only supported for Ollama endpoints.")
            return

        self.local_model_combo.clear()
        self.local_model_combo.addItem("Refreshing...")
        self.refresh_button.setEnabled(False)

        # Use the dedicated thread with signals for robust communication
        self.fetch_thread = FetchModelsThread(tags_url, self)
        self.fetch_thread.models_fetched.connect(self.on_models_fetched)
        self.fetch_thread.models_error.connect(self.on_models_error)
        self.fetch_thread.finished.connect(lambda: self.refresh_button.setEnabled(True))
        self.fetch_thread.start()

    def on_models_fetched(self, model_list):
        """Slot to handle successfully fetched models."""
        self.local_model_combo.clear()
        if model_list:
            self.local_model_combo.addItems(model_list)
        else:
            self.local_model_combo.addItem("No models found")
        self.refresh_button.setEnabled(True)

    def on_models_error(self, error_message):
        """Slot to handle errors during model fetching."""
        self.local_model_combo.clear()
        self.local_model_combo.addItem("Error refreshing")
        QMessageBox.warning(self, "Error", f"Could not fetch models: {error_message}")
        self.refresh_button.setEnabled(True)


    def load_settings(self):
        """Loads settings from the JSON file."""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
            else:
                settings = {} # Create empty settings if file doesn't exist

            # Load general settings
            self.tab_widget.setCurrentIndex(settings.get("provider_tab_index", 0))

            # Load Local AI settings
            local_settings = settings.get("local_ai", {})
            self.local_endpoint_edit.setText(local_settings.get("endpoint", "http://localhost:11434/api/chat"))
            self.local_model_combo.setCurrentText(local_settings.get("model", "llama3"))

            # Load Online AI settings
            online_settings = settings.get("online_ai", {})
            self.online_provider_tabs.setCurrentIndex(online_settings.get("selected_provider_index", 0))

            for provider_name, widgets in self.provider_widgets.items():
                provider_data = online_settings.get(provider_name, {})
                widgets['api_key'].setText(provider_data.get('api_key', ''))
                widgets['model'].setText(provider_data.get('model', ''))

        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"Could not load AI settings: {e}")
            QMessageBox.warning(self, "Warning", f"Could not load AI settings file: {e}")


    def save_settings(self):
        """Saves the current settings to the JSON file."""

        # Build the online_ai settings dictionary
        online_ai_settings = {
            "selected_provider_index": self.online_provider_tabs.currentIndex()
        }
        for provider_name, widgets in self.provider_widgets.items():
            online_ai_settings[provider_name] = {
                "api_key": widgets['api_key'].text(),
                "model": widgets['model'].text()
            }

        settings = {
            "provider_tab_index": self.tab_widget.currentIndex(),
            "local_ai": {
                "endpoint": self.local_endpoint_edit.text(),
                "model": self.local_model_combo.currentText()
            },
            "online_ai": online_ai_settings
        }
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            self.accept() # Close the dialog
        except IOError as e:
            QMessageBox.critical(self, "Error", f"Could not save AI settings: {e}")

    def _test_api_connection(self, provider_name):
        widgets = self.provider_widgets.get(provider_name)
        if not widgets:
            return

        api_key = widgets['api_key'].text()
        if not api_key:
            QMessageBox.warning(self, "API Key Missing", f"Please enter an API key for {provider_name} before testing.")
            return

        widgets['test_btn'].setText("Testing...")
        widgets['test_btn'].setEnabled(False)

        self.test_thread = TestAPIThread(provider_name, api_key, self)
        self.test_thread.success.connect(self._on_test_success)
        self.test_thread.error.connect(self._on_test_error)
        self.test_thread.finished.connect(lambda: widgets['test_btn'].setText("Test Connection"))
        self.test_thread.finished.connect(lambda: widgets['test_btn'].setEnabled(True))
        self.test_thread.start()

    def _on_test_success(self, message):
        QMessageBox.information(self, "Connection Successful", message)

    def _on_test_error(self, message):
        QMessageBox.warning(self, "Connection Failed", message)


class AIAnalysisDialog(QDialog):
    """A dialog to show the results of AI analysis."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Analysis")
        self.setMinimumSize(600, 400)

        layout = QVBoxLayout(self)
        self.results_text = QTextEdit("Analyzing... Please wait.")
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)

        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy to Clipboard")
        copy_button.clicked.connect(self.copy_results)
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addStretch()
        button_layout.addWidget(copy_button)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def set_results(self, text):
        self.results_text.setPlainText(text)

    def set_error(self, text):
        self.results_text.setPlainText(f"An error occurred:\n\n{text}")

    def copy_results(self):
        QApplication.clipboard().setText(self.results_text.toPlainText())


class AIGuideDialog(QDialog):
    """A dialog to show the user guide for AI features."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Features Guide for GScapy + AI")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout(self)
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)

        guide_html = """
        <html>
        <head>
            <style>
                body { font-family: sans-serif; line-height: 1.6; }
                h1, h2, h3 { color: #4a90e2; }
                code { background-color: #2d313a; padding: 2px 5px; border-radius: 4px; font-family: "Courier New", monospace; }
                a { color: #8be9fd; }
                ul { padding-left: 20px; }
                .button-icon { display: inline-block; width: 16px; height: 16px; vertical-align: middle; }
            </style>
        </head>
        <body>
            <h1>AI Integration Guide (v3.0)</h1>
            <p>This guide explains how to set up and use the new AI analysis features within <b>GScapy + AI</b>.</p>

            <h2>1. Setting Up an AI Service</h2>
            <p>GScapy's AI features work by connecting to a Large Language Model (LLM). You can use a local service that you run on your own machine (ensuring privacy) or an online provider.</p>

            <h3>Local AI (Recommended)</h3>
            <p>We recommend using <b>Ollama</b> or <b>LMStudio</b>.</p>
            <ol>
                <li>Download and install Ollama from <a href="https://ollama.com/">ollama.com</a>.</li>
                <li>Open your terminal and run <code>ollama pull llama3</code> to get a great general-purpose model.</li>
                <li>Ensure the service is running in the background.</li>
            </ol>

            <h3>Online AI</h3>
            <p>You can also connect to providers like OpenAI. You will need an API key from the provider.</p>

            <h2>2. Configuring GScapy + AI</h2>
            <p>You must tell GScapy how to connect to your chosen AI service.</p>
            <ol>
                <li>In the 'AI Assistant' tab, click the settings icon &#x2699; next to the 'Send' button.</li>
                <li>Click 'Advanced Settings...' to open the main configuration dialog.</li>
                <li><b>For Local AI:</b>
                    <ul>
                        <li>Go to the 'Local AI' tab.</li>
                        <li>Use the 'Detect Running Services' button to automatically find Ollama/LMStudio, or enter the endpoint manually (e.g., <code>http://localhost:11434/api/chat</code> for Ollama).</li>
                        <li>Enter the name of the model you have downloaded (e.g., <code>llama3</code>).</li>
                    </ul>
                </li>
                <li><b>For Online Services:</b>
                    <ul>
                        <li>Go to the 'Online Services' tab.</li>
                        <li>Select your provider (e.g., 'OpenAI').</li>
                        <li>Enter your API Key and the model name you wish to use (e.g., <code>gpt-4-turbo</code>).</li>
                    </ul>
                </li>
                <li>Click 'Save'.</li>
            </ol>

            <h2>3. Selecting the Active Model</h2>
            <p>The new AI settings menu makes switching between your configured models easy.</p>
            <ol>
                <li>Click the settings icon &#x2699; in the AI Assistant tab.</li>
                <li>A menu will appear showing all configured Local and Online models.</li>
                <li>Simply click on the model you want to use for your next chat. A checkmark will indicate the active model.</li>
            </ol>


            <h2>4. Using the AI Features</h2>
            <ul>
                <li><b>AI Assistant Tab:</b> The main AI tab has been redesigned.
                    <ul>
                    <li>The left panel contains a categorized list of over 70 prompts. Click any button to load the prompt into the input box.</li>
                    <li>The main chat view now uses conversational bubbles. Your prompts are on the right, and the AI's responses are on the left.</li>
                    </ul>
                </li>
                <li><b>Send to AI Analyst Button:</b> After running a scan in the Nmap, Port Scanner, or Subdomain Scanner tools, click the "Send to AI Analyst" button to automatically load the results into the AI Assistant tab for analysis.</li>
            </ul>
        </body>
        </html>
        """
        text_browser.setHtml(guide_html)
        layout.addWidget(text_browser)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button, 0, Qt.AlignmentFlag.AlignRight)


class TypingIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(40)
        self.dots = []
        self.animations = QParallelAnimationGroup(self)

        for i in range(3):
            dot = QLabel("●", self)
            dot.setStyleSheet("color: #909090; font-size: 20px;")
            self.dots.append(dot)

            anim = QPropertyAnimation(dot, b"pos")
            anim.setDuration(400)
            anim.setStartValue(QPoint(20 + i * 20, 20))
            anim.setEndValue(QPoint(20 + i * 20, 10))
            anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

            reverse_anim = QPropertyAnimation(dot, b"pos")
            reverse_anim.setDuration(400)
            reverse_anim.setStartValue(QPoint(20 + i * 20, 10))
            reverse_anim.setEndValue(QPoint(20 + i * 20, 20))
            reverse_anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

            seq = QSequentialAnimationGroup()
            seq.addPause(i * 150)
            seq.addAnimation(anim)
            seq.addAnimation(reverse_anim)
            seq.setLoopCount(-1) # Loop indefinitely
            self.animations.addAnimation(seq)

    def start_animation(self):
        self.animations.start()

    def stop_animation(self):
        self.animations.stop()


class ThinkingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_expanded = True
        self._init_ui()
        self.set_stylesheet() # Apply theme-aware styles

    def _init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.header_frame = QFrame()
        header_layout = QHBoxLayout(self.header_frame)
        header_layout.setContentsMargins(5, 5, 5, 5)

        self.toggle_button = QPushButton("Thinking...")
        self.toggle_button.setStyleSheet("border: none; text-align: left; font-weight: bold;")
        self.toggle_button.clicked.connect(self.toggle_content)

        self.arrow_label = QLabel("\u25BC") # Down-pointing arrow
        self.arrow_label.setStyleSheet("border: none;")

        header_layout.addWidget(self.toggle_button)
        header_layout.addStretch()
        header_layout.addWidget(self.arrow_label)

        self.content_widget = QTextEdit()
        self.content_widget.setReadOnly(True)

        self.main_layout.addWidget(self.header_frame)
        self.main_layout.addWidget(self.content_widget)
        self.adjustSize()

    def set_stylesheet(self):
        """Sets theme-aware stylesheet."""
        palette = self.palette()
        base_color = palette.color(QPalette.ColorRole.Base)
        # A color slightly lighter/darker than the base for the header
        header_color = base_color.lighter(110) if base_color.lightness() < 128 else base_color.darker(103)
        # A color for the content that is between the header and the base
        content_color = base_color.lighter(105) if base_color.lightness() < 128 else base_color.darker(101)
        border_color = palette.color(QPalette.ColorRole.Mid).name()
        text_color = palette.color(QPalette.ColorRole.Text).name()
        muted_text_color = palette.color(QPalette.ColorRole.Mid).name()

        self.header_frame.setStyleSheet(f"background-color: {header_color.name()}; border-radius: 5px;")
        self.content_widget.setStyleSheet(f"""
            background-color: {content_color.name()};
            border: 1px solid {border_color};
            border-top: none;
            border-radius: 5px;
            color: {muted_text_color};
        """)
        self.toggle_button.setStyleSheet(f"border: none; text-align: left; font-weight: bold; color: {text_color};")
        self.arrow_label.setStyleSheet(f"border: none; color: {text_color};")

    def toggle_content(self):
        self.is_expanded = not self.is_expanded
        self.content_widget.setVisible(self.is_expanded)
        self.arrow_label.setText("\u25BC" if self.is_expanded else "\u25B6")

        # We need to inform the list view that our size has changed.
        # A simple way is to update the geometry of the top-level widget.
        if self.parentWidget():
            self.parentWidget().updateGeometry()
            # Find the QListWidgetItem this widget belongs to and update its size hint
            for i in range(self.parentWidget().count()):
                item = self.parentWidget().item(i)
                widget = self.parentWidget().itemWidget(item)
                if widget is self:
                    item.setSizeHint(self.sizeHint())
                    break

    def append_text(self, text):
        self.content_widget.append(text)
        self.adjustSize()
        if self.parentWidget():
             self.parentWidget().updateGeometry()

    def is_collapsed(self):
        return not self.is_expanded


class ChatBubble(QFrame):
    """
    A QFrame-based chat bubble that correctly handles dynamic text resizing,
    word wrapping, and theming using a QTextBrowser for robust rendering.
    """
    def __init__(self, text, is_user, parent=None):
        super().__init__(parent)
        self.is_user = is_user

        # Main layout for the bubble
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(1, 1, 1, 1)

        # The QTextBrowser handles text display, wrapping, and selection
        self.text_browser = QTextBrowser(self)
        self.text_browser.setReadOnly(True)
        self.text_browser.setOpenExternalLinks(True)
        self.text_browser.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.text_browser.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Set a max width for the bubble based on the parent's width
        if parent:
            self.setMaximumWidth(int(parent.width() * 0.75))

        # This is the key change suggested by the code review.
        # Expanding horizontally will make it take up available space, but the alignment
        # wrapper will constrain it. Preferred vertically means it will grow as needed.
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.text_browser.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)


        # IMPORTANT: Connect the signal that triggers height adjustment.
        self.text_browser.document().contentsChanged.connect(self.on_contents_changed)

        # Set the text using a consistent method. This was the source of the regression.
        # Using insertPlainText for both initial and streamed content ensures correct behavior.
        self.text_browser.insertPlainText(text)

        # A wrapper widget to control the alignment of the bubble
        self.wrapper = QWidget()
        self.wrapper_layout = QHBoxLayout(self.wrapper)
        self.wrapper_layout.setContentsMargins(5, 2, 5, 2)
        if self.is_user:
            self.wrapper_layout.addStretch()
            self.wrapper_layout.addWidget(self)
        else:
            self.wrapper_layout.addWidget(self)
            self.wrapper_layout.addStretch()

        self.layout.addWidget(self.text_browser)
        self.set_stylesheet()

    def on_contents_changed(self):
        """Adjusts the height of the widget to match the text content."""
        doc_height = self.text_browser.document().size().height()
        # Add a small buffer for padding/margins
        self.text_browser.setFixedHeight(int(doc_height) + 15)
        # The widget's overall height will be managed by the layout system now.
        self.updateGeometry()

    def set_stylesheet(self):
        """Sets the stylesheet using the application's palette for theme-awareness."""
        palette = self.palette()
        if self.is_user:
            bg_color = palette.color(QPalette.ColorRole.Highlight).name()
            text_color = palette.color(QPalette.ColorRole.HighlightedText).name()
            border_radius = "15px"
            border_specific_radius = "border-bottom-right-radius: 3px;"
        else:
            base_color = palette.color(QPalette.ColorRole.Base)
            bg_color = base_color.lighter(115) if base_color.lightness() < 128 else base_color.darker(105)
            bg_color = bg_color.name()
            text_color = palette.color(QPalette.ColorRole.Text).name()
            border_radius = "15px"
            border_specific_radius = "border-bottom-left-radius: 3px;"

        self.setStyleSheet(f"""
            ChatBubble {{
                background-color: {bg_color};
                border-radius: {border_radius};
                {border_specific_radius}
            }}
        """)
        self.text_browser.setStyleSheet(f"""
            QTextBrowser {{
                background-color: transparent;
                border: none;
                color: {text_color};
                padding: 8px;
            }}
        """)

    def append_text(self, text_chunk):
        """Appends a chunk of text to the browser."""
        self.text_browser.insertPlainText(text_chunk)
        self.text_browser.ensureCursorVisible() # Scroll to the end

    def get_wrapper(self):
        """Returns the alignment wrapper widget."""
        return self.wrapper

class AIAssistantTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent # GScapy main window instance
        self.thinking_widget = None
        self.current_ai_bubble = None
        self.ai_thread = None
        self.completion_callback = None

        self.ai_prompts = {
            "General Security & Analysis": {
                "Summarize Findings": "Summarize the key findings from the provided security scan results. Group them by severity (Critical, High, Medium, Low) and provide a brief, non-technical explanation for each.",
                "Prioritize Remediation": "Based on the following vulnerability report, create a prioritized remediation plan. Consider the CVSS score, exploitability, and potential business impact of each finding.",
                "Explain to a CISO": "Explain the security implications of the following technical finding to a C-level executive (CISO). Focus on business risk, potential impact, and high-level recommendations.",
                "Explain to a Developer": "Explain the following web vulnerability (e.g., SQL Injection, XSS) to a developer. Provide a clear explanation of the flaw, a code example of the vulnerability, and a secure code example for remediation.",
                "Generate Report Section": "Write the 'Technical Details' section of a penetration testing report for the following vulnerability. Include a description, proof-of-concept, and remediation steps.",
                "Correlate Tool Outputs": "Correlate the findings from the following Nmap scan and Nuclei scan outputs. Are there any findings that support or confirm each other? What is the overall picture of the target's security posture?",
                "Threat Modeling": "Based on this application description, create a basic threat model using the STRIDE methodology. What are the likely threats and attack vectors?",
                "Security Checklist": "Generate a security checklist for hardening a new Ubuntu 22.04 web server that will host a public-facing website.",
                "Compare Tools": "Compare and contrast the use cases for Nmap, Masscan, and RustScan. When would I choose one over the others?",
                "Latest CVEs for Tech": "What are the most recent critical CVEs (last 6 months) for Apache Tomcat version 9.x?",
                "IOC Extraction": "Extract all Indicators of Compromise (IOCs) from the following text. Categorize them into IP addresses, domains, file hashes, and registry keys.",
                "MITRE ATT&CK Mapping": "Map the following observed attacker techniques to the MITRE ATT&CK framework. Provide the Technique ID and a brief justification.",
            },
            "Reconnaissance & OSINT": {
                "Subdomain Enumeration Strategy": "Outline a comprehensive strategy for subdomain enumeration for the domain {TARGET_DOMAIN}, using both passive and active techniques.",
                "Analyze Certificate Transparency": "Analyze the following certificate transparency log data for {TARGET_DOMAIN} and identify any unusual or potentially unauthorized subdomains.",
                "GitHub Dorking": "Provide a list of 10 advanced GitHub dorks to find sensitive information, API keys, or credentials related to {TARGET_DOMAIN}.",
                "Google Dorking for Login Pages": "Provide 5 Google dorks to find hidden login pages or admin panels for the site {TARGET_URL}.",
                "Parse JS Files for Secrets": "Analyze this JavaScript file and extract any API endpoints, hidden parameters, or developer comments that could be useful for further testing.",
                "OSINT on an Email Address": "Outline a plan to gather open-source intelligence on the email address {TARGET_EMAIL}. What tools and techniques would you use?",
                "OSINT on a Username": "Given the username {TARGET_USER}, suggest 5 websites or services, beyond what Sherlock checks, where this username might be found.",
                "Analyze WHOIS Data": "Analyze the following WHOIS record for {TARGET_DOMAIN} and point out any information that could be useful for social engineering or infrastructure mapping.",
                "Find Related Domains": "Given the domain {TARGET_DOMAIN}, what techniques can I use to find other domains owned by the same entity?",
                "Wayback Machine Analysis": "Analyze the history of {TARGET_URL} on the Wayback Machine. Are there any old, forgotten endpoints or files visible that are no longer linked on the current site?",
                "Shodan Query for IoT": "Construct a Shodan query to find exposed webcams of a specific brand (e.g., 'Axis') in a given country.",
                "Analyze Social Media Profile": "Analyze the social media profile at {PROFILE_URL} for potential OSINT clues, such as location, employer, relationships, and technical skills.",
            },
            "Network & Infrastructure Pentesting": {
                "Advanced Nmap Scan for Firewall Evasion": "Construct an advanced Nmap scan command to use against {TARGET_IP} that is designed to evade a stateful firewall. Explain each flag's purpose.",
                "Pivoting Strategy": "I have compromised a host at {COMPROMISED_IP} on the 10.10.5.0/24 subnet. Outline a strategy for pivoting from this host to scan the internal 172.16.0.0/16 network. What tools would you use?",
                "Enumerate SMB Shares": "How can I use enum4linux-ng to enumerate SMB shares on {TARGET_IP} and check for anonymous access?",
                "Null Session Exploit": "Explain the concept of an SMB null session and provide the command to test for it against {TARGET_IP} using rpcclient.",
                "LLMNR Poisoning Attack": "Describe the steps of an LLMNR/NBT-NS poisoning attack and how to perform it using Responder.",
                "Kerberoasting Explained": "What is Kerberoasting? Provide a command to attempt a Kerberoasting attack using GetUserSPNs.py.",
                "Pass-the-Hash Technique": "Explain the Pass-the-Hash (PtH) technique. How can I use pth-winexe to execute a command on {TARGET_IP} if I have an NTLM hash?",
                "Analyze SNMP Output": "Analyze the following SNMP walk output. Are there any interesting community strings, user accounts, or system information disclosed?",
                "Router Security Check": "I need to perform a security check on a router at {TARGET_IP}. What are the top 5 things I should look for?",
                "FTP Anonymous Login": "How can I check for anonymous FTP login on {TARGET_IP} and list the contents of the root directory?",
                "DNS Zone Transfer": "How can I attempt a DNS zone transfer against the domain {TARGET_DOMAIN} using `dig` or `dnsrecon`?",
                "IPv6 Network Discovery": "What are some common techniques and tools for discovering live hosts on an IPv6 network?",
            },
            "Web Application Pentesting": {
                "Test for SQL Injection": "Provide a list of 10 payloads to test for a classic, in-band SQL injection vulnerability in the URL parameter 'id' at {TARGET_URL}?id=1.",
                "Test for XSS": "Provide 5 different payloads to test for a reflected Cross-Site Scripting (XSS) vulnerability in a search bar.",
                "Test for LFI/RFI": "How would you test for Local File Inclusion (LFI) and Remote File Inclusion (RFI) on a PHP application using the parameter `?file=main.php`?",
                "Bypass File Upload Filter": "A web application only allows '.jpg' and '.png' file uploads. Suggest 5 ways to bypass this filter to upload a web shell.",
                "Identify IDOR": "Explain how to test for Insecure Direct Object References (IDORs). I have an account and can access my invoice at /invoices/105. What should I try next?",
                "Test for SSRF": "How can I test for Server-Side Request Forgery (SSRF) on a parameter like `?image_url=http://example.com/img.png`? Provide 3 payloads for different scenarios (e.g., accessing metadata service).",
                "JWT Analysis": "Analyze the following JSON Web Token (JWT). Point out any potential weaknesses. Token: {JWT_TOKEN}",
                "Fuzzing with ffuf": "Construct an ffuf command to fuzz for vhosts on {TARGET_URL} using the wordlist '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'. The keyword should be in the Host header.",
                "API Endpoint Discovery": "Outline a strategy for discovering hidden or undocumented API endpoints for the application at {TARGET_URL}.",
                "Test for Race Conditions": "Describe a scenario and methodology to test for a race condition vulnerability in a web application's coupon code feature.",
                "XML External Entity (XXE)": "Provide an XXE payload to read the `/etc/passwd` file.",
                "Deserialization Exploit": "Explain how to test for a Java deserialization vulnerability using the `ysoserial` tool.",
            },
            "Malware Analysis & DFIR": {
                "Static Malware Analysis": "I have a suspicious executable file. What are the first 5 steps I should take to perform static analysis without running the file?",
                "Dynamic Malware Analysis": "Outline a safe environment setup for dynamic malware analysis (sandboxing). What tools are essential?",
                "Analyze Obfuscated PowerShell": "De-obfuscate and explain the purpose of the following PowerShell script.",
                "YARA Rule Creation": "Write a basic YARA rule to detect a specific string ('EvilCorpC2') and a specific file section (`.bad`) in a binary.",
                "Memory Forensics with Volatility": "I have a memory dump from a compromised Windows machine. What Volatility 3 command would I use to list running processes?",
                "Analyze Phishing Email Headers": "Analyze the following email headers and determine the true origin of the email and identify any signs of spoofing.",
                "Incident Response Playbook": "Create a high-level incident response playbook for a ransomware attack.",
                "Disk Imaging": "What is the difference between a logical and a physical disk image? When would you use `dd` vs `FTK Imager`?",
                "Log Analysis for Intrusion": "Analyze the following Apache access log snippet and identify any potential web attack attempts.",
                "Network Forensics with Wireshark": "I have a .pcap file from an incident. What Wireshark filter would I use to find all DNS queries that are NOT going to the approved internal DNS server (10.1.1.5)?",
            },
            "Wireless & Cracking": {
                "WPA Handshake Capture": "What is the best way to capture a WPA/WPA2 4-way handshake from a client connected to the BSSID {TARGET_BSSID}?",
                "Deauthentication Attack": "Explain the purpose of a deauthentication attack in the context of Wi-Fi penetration testing. Provide the aireplay-ng command to perform it.",
                "Analyze a .cap file": "Analyze the provided .cap file summary. What kind of traffic does it contain and what would be the next step in assessing its security?",
                "Crack a Password Hash": "I have the following NTLM hash: {NTLM_HASH}. What is the command to crack this using John the Ripper and the rockyou.txt wordlist?",
                "Hashcat Mask Attack": "I know a password is 8 characters long, starts with a capital letter, is followed by lowercase letters, and ends with two digits. What Hashcat mask would I use for this?",
                "Evil Twin Attack": "Describe how to set up an Evil Twin attack to capture credentials. What tools are required?",
                "KRACK Attack Explained": "Explain the KRACK attack against WPA2 in simple terms. What is the core vulnerability?",
                "Bluetooth Low Energy (BLE) Hacking": "What are the first steps in assessing the security of a Bluetooth Low Energy (BLE) device? What tools would you use?",
                "RFID Cloning": "What are the risks associated with RFID access cards, and what hardware is typically used to clone them?",
                "PMKID Attack": "Explain the WPA/WPA2 PMKID attack. How is it different from the 4-way handshake attack, and what tool can be used to perform it?",
            },
            "Scripting & Automation": {
                "Generate Nmap Port Scan Script": "Generate a bash script that automates port scanning with Nmap for a list of IPs in a file named 'targets.txt' and saves the output for each IP.",
                "Create Python Scapy Script": "Write a Python script using Scapy to send a TCP SYN packet to port 80 of a target IP address and print whether the port is open or closed.",
                "Automate Log Analysis with Python": "Write a Python script to parse an Apache access log file and identify the top 10 IP addresses with the most requests.",
                "PowerShell for User Audit": "Write a PowerShell script to audit all local user accounts on a Windows machine and flag any that have not been logged into for over 90 days.",
                "Bash Script to Check for Open Ports": "Create a simple bash script that uses 'netcat' to check if a specific port is open on a given host.",
                "Detect Registry Changes with ELK": "Provide an ELK query to detect changes in the Windows Registry, specifically focusing on keys related to startup programs.",
                "Python Script to Detect XSS": "Write a Python script that takes a URL as input and checks for basic reflected XSS vulnerabilities by testing common payloads in URL parameters.",
                "Automate Subdomain Enumeration": "Create a bash script that chains together 'subfinder' and 'httpx' to find live subdomains for a given domain.",
                "PowerShell to Disable Inactive Accounts": "Write a PowerShell script for Active Directory that finds user accounts that have been inactive for 60 days and disables them.",
                "Python Script for Password Strength": "Write a Python script that takes a password as input and rates its strength based on length, and inclusion of uppercase, lowercase, numbers, and symbols.",
            },
            "Policy & Compliance": {
                "Draft Data Protection Policy": "Provide guidance on drafting a data protection and privacy policy in accordance with GDPR for a small e-commerce company.",
                "Update Security Policies": "Review the following (outdated) security policy and suggest updates to align with modern industry best practices and the evolving threat landscape.",
                "Develop Password Management Policy": "Assist in developing a password management policy that promotes strong, unique passwords and the use of multi-factor authentication (MFA).",
                "Create Mobile Device Policy (BYOD)": "Offer recommendations for creating a mobile device management policy (MDM) to secure employee-owned devices (BYOD) and protect corporate data.",
                "Establish Network Access Control Policy": "Assist in establishing a network access control (NAC) policy to ensure only authorized and compliant devices can connect to the organization’s network.",
                "Outline Incident Response Policy": "Provide guidance on creating an incident response policy that clearly outlines roles, responsibilities, communication channels, and escalation procedures.",
                "Define Patch Management Policy": "Help define a patch management policy that ensures timely updates and vulnerability remediation across all systems and software, with a focus on critical assets.",
                "Develop Encryption Policy": "Assist in developing a data encryption policy to protect sensitive data at rest and in transit, specifying required algorithms and key management procedures.",
                "Create Employee Training Policy": "Guide the creation of an employee security training and awareness policy to promote a security-conscious culture within the organization.",
                "Generate ROE Report": "You are a senior penetration testing engagement manager. Based on the provided target scope, generate a formal Rules of Engagement (ROE) document in Markdown format.",
            },
        }

        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # --- Left Panel: Prompts ---
        self.prompt_tree = QTreeWidget()
        self.prompt_tree.setHeaderHidden(True)
        self.prompt_tree.itemClicked.connect(self._on_prompt_selected)
        self._populate_prompts()
        splitter.addWidget(self.prompt_tree)

        # --- Right Panel: Chat ---
        chat_container = QWidget()
        chat_layout = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(10, 10, 10, 10)
        chat_layout.setSpacing(6)

        # Header
        header = QTextBrowser()
        header.setHtml("""
            <div align="center">
                <h2>GScapy + AI Assistant</h2>
                <p>Your smart, context-aware cybersecurity assistant.</p>
            </div>
        """)
        header.setFixedHeight(80)
        header.setStyleSheet("QTextBrowser { border: none; background: transparent; }")
        chat_layout.addWidget(header)

        # Chat message area using QScrollArea
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")

        self.scroll_content_widget = QWidget()
        self.chat_scroll_layout = QVBoxLayout(self.scroll_content_widget)
        self.chat_scroll_layout.addStretch() # Pushes bubbles to the top
        self.scroll_area.setWidget(self.scroll_content_widget)
        chat_layout.addWidget(self.scroll_area)

        # Typing indicator
        self.typing_indicator = TypingIndicator(self)
        self.typing_indicator.setFixedHeight(30)
        self.typing_indicator.hide()
        chat_layout.addWidget(self.typing_indicator)

        # Bottom input controls
        bottom_controls_layout = QHBoxLayout()
        self.input_frame = QFrame(self)
        self.input_frame.setObjectName("inputFrame")
        input_frame_layout = QHBoxLayout(self.input_frame)
        input_frame_layout.setContentsMargins(15, 5, 5, 5)
        input_frame_layout.setSpacing(10)

        self.user_input = QLineEdit(self)
        self.user_input.setPlaceholderText("Ask the AI Assistant...")
        self.user_input.setStyleSheet("border: none; background-color: transparent; font-size: 14px;")
        input_frame_layout.addWidget(self.user_input)

        self.send_button = QPushButton()
        self.send_button.setFixedSize(30, 30)
        self.send_button.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        self.send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_button.setToolTip("Send Message")
        input_frame_layout.addWidget(self.send_button)

        bottom_controls_layout.addWidget(self.input_frame)

        self.ai_settings_btn = QPushButton()
        self.ai_settings_btn.setToolTip("Configure & Select AI Models")
        self.ai_settings_btn.setFixedSize(40, 40)
        self.ai_settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_settings_btn.setStyleSheet("QPushButton { border: none; background-color: transparent; }")
        bottom_controls_layout.addWidget(self.ai_settings_btn)

        chat_layout.addLayout(bottom_controls_layout)
        splitter.addWidget(chat_container)
        splitter.setSizes([250, 750])

        # --- Connections ---
        self.send_button.clicked.connect(self.send_message)
        self.user_input.returnPressed.connect(self.send_message)
        self.ai_settings_btn.clicked.connect(self._show_ai_settings_menu)

        self.update_theme() # Set initial themed icons and styles

    def update_theme(self):
        """Updates the icon color and other theme-dependent widgets."""
        palette = self.palette()
        text_color = palette.color(QPalette.ColorRole.WindowText).name()
        base_color = palette.color(QPalette.ColorRole.Base).name()
        border_color = palette.color(QPalette.ColorRole.Mid).name()

        # Update icons
        self.ai_settings_btn.setIcon(create_themed_icon(os.path.join("icons", "gear.svg"), text_color))
        self.ai_settings_btn.setIconSize(QSize(24, 24))
        self.send_button.setIcon(create_themed_icon(os.path.join("icons", "paper-airplane.svg"), text_color))
        self.send_button.setIconSize(QSize(24, 24))

        # Update input bar style
        self.input_frame.setStyleSheet(f"""
            #inputFrame {{
                border: 1px solid {border_color};
                border-radius: 18px;
                background-color: {base_color};
            }}
        """)

        # Update any existing chat bubbles
        for i in range(self.chat_scroll_layout.count()):
            widget = self.chat_scroll_layout.itemAt(i).widget()
            if widget:
                # The widget in the layout is the wrapper.
                bubble = widget.findChild(ChatBubble)
                if bubble:
                    bubble.set_stylesheet()
                thinking_widget = widget.findChild(ThinkingWidget)
                if thinking_widget:
                    thinking_widget.set_stylesheet()

    def _populate_prompts(self):
        for category, prompts in self.ai_prompts.items():
            category_item = QTreeWidgetItem(self.prompt_tree, [category])
            font = category_item.font(0)
            font.setBold(True)
            category_item.setFont(0, font)
            category_item.setFlags(category_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            for prompt_name, prompt_text in prompts.items():
                prompt_item = QTreeWidgetItem(category_item, [prompt_name])
                prompt_item.setData(0, Qt.ItemDataRole.UserRole, prompt_text)
                prompt_item.setToolTip(0, prompt_text)

    def _on_prompt_selected(self, item, column):
        if item and item.parent():
            prompt_text = item.data(0, Qt.ItemDataRole.UserRole)
            if prompt_text:
                self.user_input.setText(prompt_text)

    def _add_chat_bubble(self, message, is_user, is_streaming=False):
        # Create the bubble and its alignment wrapper
        bubble = ChatBubble(message, is_user, parent=self.scroll_content_widget)
        bubble_wrapper = bubble.get_wrapper()

        # Insert the new bubble before the stretch item
        self.chat_scroll_layout.insertWidget(self.chat_scroll_layout.count() - 1, bubble_wrapper)

        # Force the UI to process the new widget addition immediately
        QApplication.processEvents()

        # Scroll to the bottom to show the new message
        QTimer.singleShot(50, lambda: self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum()))

        if is_streaming:
            return bubble
        return None

    def _show_typing_indicator(self, show=True):
        if show:
            self.typing_indicator.show()
            self.typing_indicator.start_animation()
        else:
            self.typing_indicator.hide()
            self.typing_indicator.stop_animation()

    def send_message(self):
        user_text = self.user_input.text().strip()
        if not user_text:
            return
        self._add_chat_bubble(user_text, is_user=True)
        self.user_input.clear()
        self.start_ai_analysis(user_text)

    def start_ai_analysis(self, prompt):
        # This will require the parent (main window) to have this method
        ai_settings = self.parent.get_ai_settings()
        if not ai_settings:
            self.handle_ai_error("AI settings are not configured. Please configure them in the main window.")
            return
        self._show_typing_indicator(True)
        self.ai_thread = AIAnalysisThread(prompt, ai_settings, self)
        self.ai_thread.response_ready.connect(self.handle_ai_response)
        self.ai_thread.error.connect(self.handle_ai_error)
        self.ai_thread.finished.connect(self.on_ai_thread_finished)
        self.ai_thread.start()

    def handle_ai_response(self, chunk, is_thinking, is_final_answer_chunk):
        self._show_typing_indicator(False)

        scroll_bar = self.scroll_area.verticalScrollBar()
        is_at_bottom = (scroll_bar.value() >= scroll_bar.maximum() - 10)

        if is_thinking:
            if not self.thinking_widget:
                self.thinking_widget = ThinkingWidget()
                self.chat_scroll_layout.insertWidget(self.chat_scroll_layout.count() - 1, self.thinking_widget)
            self.thinking_widget.append_text(chunk)
        else:
            if self.thinking_widget:
                self.thinking_widget.hide()
                self.thinking_widget.deleteLater()
                self.thinking_widget = None

            if self.current_ai_bubble is None:
                self.current_ai_bubble = self._add_chat_bubble("", is_user=False, is_streaming=True)

            if self.current_ai_bubble:
                self.current_ai_bubble.append_text(chunk)

        if is_at_bottom:
            QTimer.singleShot(50, lambda: scroll_bar.setValue(scroll_bar.maximum()))

    def set_completion_callback(self, callback):
        """Sets a one-time callback to be executed when AI analysis completes."""
        self.completion_callback = callback

    def on_ai_thread_finished(self):
        self._show_typing_indicator(False)

        final_text = ""
        if self.current_ai_bubble:
            final_text = self.current_ai_bubble.text_browser.toPlainText()

        if self.completion_callback and final_text:
            try:
                self.completion_callback(final_text)
            except Exception as e:
                logging.error(f"Error executing AI completion callback: {e}")
            finally:
                self.completion_callback = None # Reset callback after use

        self.thinking_widget = None
        self.current_ai_bubble = None

    def handle_ai_error(self, error_message):
        self._show_typing_indicator(False)
        self._add_chat_bubble(f"Error: {error_message}", is_user=False)
        if self.thinking_widget: self.thinking_widget.hide()
        self.thinking_widget = None
        self.current_ai_bubble = None

    def send_to_analyst(self, tool_name, results_data=None, context=None):
        formatted_results, header = "", ""
        if tool_name == "nmap":
            header = f"Nmap scan results for target: {context}"
            if results_data:
                # This part will fail because lxml is not imported here.
                # This needs to be handled during integration.
                formatted_results = results_data
            else: formatted_results = "No Nmap XML data available."
        elif tool_name == "subdomain":
            header = f"Subdomain scan for: {context}"
            formatted_results = "\n".join([results_data.topLevelItem(i).text(0) for i in range(results_data.topLevelItemCount())])
        elif tool_name == "port_scanner":
            header = f"Port scan for: {context}"
            formatted_results = "\n".join([f"Port {p} is {s} ({srv})" for p, s, srv in results_data])

        if not formatted_results.strip():
            QMessageBox.information(self, "No Data", "No data to send.")
            return

        full_text = f"Analyze the following from {tool_name} and summarize potential vulnerabilities or next steps.\n\n--- {header} ---\n{formatted_results}\n--- END ---"
        self.user_input.setText(full_text)
        # This will require the parent to have a tab_widget attribute
        self.parent.tab_widget.setCurrentWidget(self)

    def _show_ai_settings_menu(self):
        settings_file = "ai_settings.json"
        try:
            settings = {}
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f: settings = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Error", f"Could not load AI settings: {e}"); return

        menu = QMenu(self)
        provider_group = QActionGroup(self)
        provider_group.setExclusive(True)
        active_provider = settings.get("active_provider")
        active_model = settings.get("active_model")

        # Local AI
        local_settings = settings.get("local_ai", {})
        if local_model_name := local_settings.get("model"):
            action = QAction(f"Local: {local_model_name}", self, checkable=True)
            if active_provider == "local_ai": action.setChecked(True)
            action.triggered.connect(lambda chk, p="local_ai", m=local_model_name: self._set_active_ai_provider(p, m))
            provider_group.addAction(action)
            menu.addAction(action)

        # Online Services
        online_menu = menu.addMenu("Online Services")
        online_settings = settings.get("online_ai", {})
        online_options_exist = False
        for name in ["OpenAI", "Gemini", "Grok", "DeepSeek", "Qwen"]:
            if (p_data := online_settings.get(name, {})) and p_data.get("api_key") and p_data.get("model"):
                online_options_exist = True
                action = QAction(f"{name}: {p_data['model']}", self, checkable=True)
                if active_provider == name: action.setChecked(True)
                action.triggered.connect(lambda chk, p=name, m=p_data['model']: self._set_active_ai_provider(p, m))
                provider_group.addAction(action)
                online_menu.addAction(action)
        online_menu.setEnabled(online_options_exist)

        menu.addSeparator()
        # This will require the parent to have this method
        menu.addAction("Advanced Settings...", self.parent._show_ai_settings_dialog)
        menu.exec(self.ai_settings_btn.mapToGlobal(self.ai_settings_btn.rect().bottomLeft()))

    def _set_active_ai_provider(self, provider, model):
        settings_file = "ai_settings.json"
        try:
            settings = {}
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f: settings = json.load(f)
            settings['active_provider'] = provider
            settings['active_model'] = model
            with open(settings_file, 'w') as f: json.dump(settings, f, indent=4)
            QMessageBox.information(self, "AI Model Changed", f"Active model set to:\n{provider}: {model}")
            logging.info(f"AI Provider set to {provider} ({model})")
        except (IOError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Error", f"Could not save AI settings: {e}")
