import os
import re
import os
import sys
import time
from datetime import datetime
from io import StringIO

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QCheckBox, QLabel, QDialog, QMessageBox, QTreeWidget,
    QTreeWidgetItem, QStackedWidget, QTextEdit, QSplitter, QComboBox,
    QMenu, QApplication, QAbstractItemView, QTextBrowser, QGroupBox,
    QProgressBar, QRadioButton, QButtonGroup, QFormLayout, QGridLayout,
    QInputDialog, QGraphicsOpacityEffect, QToolButton, QTableView,
    QDateEdit, QSpinBox, QTreeView, QStatusBar
)
from PyQt6.QtCore import (
    Qt, pyqtSignal, QThread, QMimeData, QUrl, QTimer, QObject, QRunnable, QThreadPool, pyqtSlot
)
from PyQt6.QtGui import (
    QIcon, QTextCursor, QKeySequence, QShortcut, QFileSystemModel, QFont
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebChannel import QWebChannel

import paramiko
from paramiko.ssh_exception import SSHException

# Import database functions (optional)
try:
    from database import (
        add_ssh_connection,
        update_ssh_connection,
        delete_ssh_connection,
        get_ssh_connection,
        get_all_ssh_connections,
    )
except ImportError:
    def add_ssh_connection(**kwargs): pass
    def update_ssh_connection(*args, **kwargs): pass
    def delete_ssh_connection(conn_id): pass
    def get_ssh_connection(conn_id): return None
    def get_all_ssh_connections(): return []


# =============== Worker Threads ===============
class ShellReaderWorker(QThread):
    output_received = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, shell_channel, log_file_path):
        super().__init__()
        self.shell_channel = shell_channel
        self.log_file_path = log_file_path
        self._stop = False

    def run(self):
        try:
            while not self._stop and self.shell_channel and not self.shell_channel.closed:
                if self.shell_channel.recv_ready():
                    data = self.shell_channel.recv(1024)
                    if data:
                        decoded = data.decode('utf-8', errors='replace')
                        try:
                            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                                f.write(decoded)
                        except Exception:
                            pass
                        self.output_received.emit(decoded)
                else:
                    self.msleep(10)
        except Exception as e:
            # «««««««««««««««««««««««
            print(f"!!!!!!!!!!!!!!! ShellReaderWorker CRASHED: {e}")
            # «««««««««««««««««««««««
        finally:
            self.finished.emit()

    def stop(self):
        self._stop = True


class FileTransferWorker(QRunnable):
    def __init__(self, func):
        super().__init__()
        self.func = func

    def run(self):
        try:
            self.func()
        except Exception as e:
            print(f"Transfer error: {e}")


# =============== Bridge for xterm.js ===============
class TerminalBridge(QObject):
    data_received = pyqtSignal(str)
    resize_requested = pyqtSignal(int, int)
    ready = pyqtSignal()

    @pyqtSlot(str)
    def send(self, data):
        self.data_received.emit(data)

    @pyqtSlot(int, int)
    def resize(self, cols, rows):
        self.resize_requested.emit(cols, rows)

    @pyqtSlot()
    def on_ready_js(self):
        self.ready.emit()


# =============== Xterm-based Terminal Widget ===============
class XtermWidget(QWidget):
    def __init__(self, parent_tab=None):
        super().__init__()
        self.parent_tab = parent_tab
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        layout.addWidget(self.web_view)

        self.bridge = TerminalBridge()
        self.channel = QWebChannel()
        self.channel.registerObject("pywebview", self.bridge)
        self.web_view.page().setWebChannel(self.channel)

        html_content = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body, html {
            margin: 0;
            padding: 0;
            background: #000;
            overflow: hidden;
        }
        #terminal {
            width: 100vw;
            height: 100vh;
        }
    </style>

    <script src="xterm_lib/xterm.min.js"></script>
    <script src="xterm_lib/xterm-addon-fit.min.js"></script>
    <link rel="stylesheet" href="xterm_lib/xterm.css" />

    <script src="qwebchannel.js"></script>

</head>
<body>
    <div id="terminal"></div>
<script>
        var pywebview_bridge = null;
        const term = new Terminal({
            cursorBlink: true,
            rows: 30,
            cols: 120
        });

        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        
        term.open(document.getElementById('terminal'));
        
        fitAddon.fit();
        
        window.onresize = () => fitAddon.fit();
        
        term.focus();

        window.receiveData = function(data) {
            term.write(data);
        }

        term.onData(data => {
            if (pywebview_bridge) {
                pywebview_bridge.send(data);
            }
        });

        term.onResize(size => {
            if (pywebview_bridge) {
                pywebview_bridge.resize(size.cols, size.rows);
            }
        });

        console.log("JS: Script loaded.");
        if (typeof window.QWebChannel === 'undefined') {
            console.error("JS FATAL: QWebChannel class is not defined! qwebchannel.js failed to load or run.");
        } else {
            console.log("JS: QWebChannel class is loaded.");
        }

        if (typeof qt === 'undefined' || typeof qt.webChannelTransport === 'undefined') {
            console.error("JS FATAL: qt.webChannelTransport is not defined!");
        } else {
            console.log("JS: qt.webChannelTransport is available.");
        }

        console.log("JS: Attempting QWebChannel connection...");
        try {
            new QWebChannel(qt.webChannelTransport, function (channel) {
                console.log("JS: QWebChannel connection ESTABLISHED!");
                pywebview_bridge = channel.objects.pywebview;

                if (pywebview_bridge && pywebview_bridge.on_ready_js) {
                    console.log("JS: Found pywebview_bridge. Calling on_ready_js()...");
                    pywebview_bridge.on_ready_js();
                } else {
                    console.error("JS ERROR: pywebview_bridge or on_ready_js not found!");
                }
            });
        } catch (e) {
            console.error("JS CRITICAL: 'new QWebChannel' call FAILED with exception:", e);
        }
    </script>
</body>
</html>'''

        html_path = os.path.join(os.path.dirname(__file__), "xterm_bridge.html")
        if not os.path.exists(html_path):
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        self.web_view.load(QUrl.fromLocalFile(html_path))
        self.web_view.loadFinished.connect(self.on_load_finished)

        self._is_ready = False
        self._pending_data = []

        # ✅ حالا ready یک سیگنال است و connect کار می‌کند
        self.bridge.ready.connect(self._on_ready)
        self.bridge.data_received.connect(self._on_user_input)
        self.bridge.resize_requested.connect(self._on_resize)

    def on_load_finished(self, ok):
        if not ok:
            print("[ERROR] Failed to load xterm_bridge.html")

    def _on_ready(self):
        self._is_ready = True
        for data in self._pending_data:
            self._write_raw(data)
        self._pending_data.clear()

    def _on_user_input(self, data):
        if self.parent_tab and self.parent_tab.shell_channel:
            self.parent_tab.shell_channel.send(data)

    def _on_resize(self, cols, rows):
        if self.parent_tab and self.parent_tab.shell_channel:
            try:
                self.parent_tab.shell_channel.resize_pty(width=cols, height=rows)
            except Exception as e:
                print(f"Resize error: {e}")

    def write(self, data):
        if self._is_ready:
            self._write_raw(data)
        else:
            self._pending_data.append(data)

    def _write_raw(self, data):
        script = f"window.receiveData({repr(data)});"
        self.web_view.page().runJavaScript(script)

    def set_theme(self, theme_name):
        themes = {
            "Default Dark": ("#000000", "#00ff00"),
            "Solarized Light": ("#fdf6e3", "#657b83"),
            "Solarized Dark": ("#002b36", "#839496"),
            "Monokai": ("#272822", "#f8f8f2"),
        }
        bg, fg = themes.get(theme_name, ("#000000", "#00ff00"))
        script = f"""
        document.body.style.background = '{bg}';
        term.setOption('theme', {{ background: '{bg}', foreground: '{fg}' }});
        """
        self.web_view.page().runJavaScript(script)

    def copy(self):
        self.web_view.triggerPageAction(QWebEngineView.WebAction.Copy)

    def paste(self):
        clipboard = QApplication.clipboard()
        clip_text = clipboard.text()
        if clip_text and self.parent_tab and self.parent_tab.shell_channel:
            self.parent_tab.shell_channel.send(clip_text)

    def setFocus(self):
        self.web_view.setFocus()


# =============== Text Preview Dialog ===============
class TextPreviewDialog(QDialog):
    def __init__(self, title, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Preview: {title}")
        self.resize(800, 600)
        layout = QVBoxLayout(self)
        browser = QTextBrowser()
        browser.setPlainText(content)
        layout.addWidget(browser)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


# =============== Main SSH Manager Tab ===============
class SshManagerTab(QWidget):
    def __init__(self, icon_path_func, parent=None):
        super().__init__(parent)
        self.icon_path = icon_path_func
        self.ssh_client = None
        self.sftp_client = None
        self.shell_channel = None
        self.read_worker = None
        self.current_remote_path = "/"
        self.session_log = ""
        self.log_file_path = None
        self.thread_pool = QThreadPool()
        self.init_ui()
        self.load_connections()

    def init_ui(self):
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        self.connection_tree = QTreeWidget()
        self.connection_tree.setHeaderLabels(["Saved Connections"])
        self.connection_tree.itemDoubleClicked.connect(self.connect_to_selected)
        left_layout.addWidget(self.connection_tree)

        conn_button_layout = QHBoxLayout()
        self.add_conn_button = QPushButton(QIcon(self.icon_path("plus-circle.svg")), " Add")
        self.edit_conn_button = QPushButton(QIcon(self.icon_path("edit.svg")), " Edit")
        self.delete_conn_button = QPushButton(QIcon(self.icon_path("trash-2.svg")), " Delete")
        conn_button_layout.addWidget(self.add_conn_button)
        conn_button_layout.addWidget(self.edit_conn_button)
        conn_button_layout.addWidget(self.delete_conn_button)
        left_layout.addLayout(conn_button_layout)
        main_splitter.addWidget(left_panel)

        # Right Panel
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        self.interaction_stack = QStackedWidget()

        # Terminal
        terminal_container = QWidget()
        terminal_layout = QVBoxLayout(terminal_container)
        self.terminal_output = XtermWidget(self)
        terminal_layout.addWidget(self.terminal_output)

        # Search bar
        self.search_widget = QWidget()
        search_layout = QHBoxLayout(self.search_widget)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Find in terminal...")
        self.search_prev_btn = QPushButton("Prev")
        self.search_next_btn = QPushButton("Next")
        self.search_close_btn = QPushButton("✕")
        search_layout.addWidget(QLabel("Find:"))
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.search_prev_btn)
        search_layout.addWidget(self.search_next_btn)
        search_layout.addWidget(self.search_close_btn)
        self.search_widget.setVisible(False)
        terminal_layout.addWidget(self.search_widget)
        self.interaction_stack.addWidget(terminal_container)

        # SFTP Panel
        sftp_widget = QWidget()
        sftp_layout = QVBoxLayout(sftp_widget)
        sftp_splitter = QSplitter(Qt.Orientation.Horizontal)

        local_panel = QWidget()
        local_layout = QVBoxLayout(local_panel)
        local_layout.addWidget(QLabel("Local System"))
        self.local_model = QFileSystemModel()
        self.local_model.setRootPath("")
        self.local_file_tree = QTreeView()
        self.local_file_tree.setModel(self.local_model)
        self.local_file_tree.setRootIndex(self.local_model.index(os.path.expanduser("~")))
        self.local_file_tree.setSortingEnabled(True)
        self.local_file_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        local_layout.addWidget(self.local_file_tree)
        sftp_splitter.addWidget(local_panel)

        remote_panel = QWidget()
        remote_layout = QVBoxLayout(remote_panel)
        remote_layout.addWidget(QLabel("Remote System"))
        self.remote_file_tree = QTreeWidget()
        self.remote_file_tree.setHeaderLabels(["Name", "Size", "Modified"])
        self.remote_file_tree.itemDoubleClicked.connect(self.remote_item_double_clicked)
        self.remote_file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.remote_file_tree.customContextMenuRequested.connect(self.remote_context_menu)
        remote_layout.addWidget(self.remote_file_tree)
        sftp_splitter.addWidget(remote_panel)

        sftp_layout.addWidget(sftp_splitter)
        self.interaction_stack.addWidget(sftp_widget)

        right_layout.addWidget(self.interaction_stack)

        # Top Controls
        top_control_layout = QHBoxLayout()
        self.connect_button = QPushButton(QIcon(self.icon_path("log-in.svg")), " Connect")
        self.disconnect_button = QPushButton(QIcon(self.icon_path("log-out.svg")), " Disconnect")
        self.switch_to_terminal_button = QPushButton("Terminal")
        self.switch_to_sftp_button = QPushButton("SFTP / SCP")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Default Dark", "Solarized Light", "Solarized Dark", "Monokai"])
        self.theme_combo.currentTextChanged.connect(self.apply_terminal_theme)
        top_control_layout.addWidget(self.connect_button)
        top_control_layout.addWidget(self.disconnect_button)
        top_control_layout.addStretch()
        top_control_layout.addWidget(QLabel("Theme:"))
        top_control_layout.addWidget(self.theme_combo)
        top_control_layout.addWidget(self.switch_to_terminal_button)
        top_control_layout.addWidget(self.switch_to_sftp_button)
        right_layout.addLayout(top_control_layout)

        # Status Bar
        self.status_bar = QStatusBar()
        self.status_label = QLabel("Disconnected")
        self.status_bar.addWidget(self.status_label)
        right_layout.addWidget(self.status_bar)

        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([200, 600])
        main_layout = QHBoxLayout(self)
        main_layout.addWidget(main_splitter)
        self.setLayout(main_layout)

        # Connections
        self.add_conn_button.clicked.connect(self.add_connection)
        self.edit_conn_button.clicked.connect(self.edit_connection)
        self.delete_conn_button.clicked.connect(self.delete_connection)
        self.connect_button.clicked.connect(self.connect_to_selected)
        self.disconnect_button.clicked.connect(self.disconnect_ssh)
        self.switch_to_terminal_button.clicked.connect(lambda: self.interaction_stack.setCurrentIndex(0))
        self.switch_to_sftp_button.clicked.connect(lambda: self.interaction_stack.setCurrentIndex(1))

        self.search_close_btn.clicked.connect(lambda: self.search_widget.setVisible(False))

        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(lambda: self.interaction_stack.setCurrentIndex(0))
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self.show_search_bar)

    def show_search_bar(self):
        QMessageBox.information(self, "Not Implemented", "Search in terminal will be added in a future update.")

    def apply_terminal_theme(self, theme_name):
        self.terminal_output.set_theme(theme_name)

    def load_connections(self):
        self.connection_tree.clear()
        try:
            connections = get_all_ssh_connections()
            for conn in connections:
                item = QTreeWidgetItem([conn["name"]])
                item.setData(0, Qt.ItemDataRole.UserRole, conn)
                self.connection_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load SSH connections: {e}")

    def add_connection(self):
        dialog = SshConnectDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            if not data:
                return
            try:
                add_ssh_connection(
                    name=data["name"], host=data["host"], port=data["port"],
                    username=data["username"], password=data["password"], private_key=data["private_key"]
                )
                self.load_connections()
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to save connection: {e}")

    def edit_connection(self):
        selected_item = self.connection_tree.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No Selection", "Please select a connection to edit.")
            return
        conn_data = selected_item.data(0, Qt.ItemDataRole.UserRole)
        conn_id = conn_data['id']
        try:
            full_conn_data = get_ssh_connection(conn_id)
            if not full_conn_data:
                QMessageBox.critical(self, "Error", f"Could not retrieve connection details for ID {conn_id}.")
                return
            dialog = SshConnectDialog(self, full_conn_data)
            if dialog.exec():
                new_data = dialog.get_data()
                if not new_data:
                    return
                update_ssh_connection(
                    conn_id, name=new_data["name"], host=new_data["host"], port=new_data["port"],
                    username=new_data["username"], password=new_data["password"], private_key=new_data["private_key"]
                )
                self.load_connections()
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to edit connection: {e}")

    def delete_connection(self):
        selected_item = self.connection_tree.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No Selection", "Please select a connection to delete.")
            return
        reply = QMessageBox.question(self, "Confirm Delete", "Are you sure you want to delete this connection?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn_data = selected_item.data(0, Qt.ItemDataRole.UserRole)
            try:
                delete_ssh_connection(conn_data['id'])
                self.load_connections()
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete connection: {e}")

    def connect_to_selected(self):
        selected_item = self.connection_tree.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No Selection", "Please select a connection to connect to.")
            return
        conn_summary = selected_item.data(0, Qt.ItemDataRole.UserRole)
        conn_id = conn_summary['id']
        try:
            full_conn_data = get_ssh_connection(conn_id)
            if not full_conn_data:
                QMessageBox.critical(self, "Error", "Could not retrieve connection details to connect.")
                return
            self.connect_ssh(full_conn_data)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to retrieve connection details: {e}")

    def connect_ssh(self, config):
        self.disconnect_ssh()
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.session_log = ""

            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_file_path = os.path.join(log_dir, f"ssh_{config['host']}_{timestamp}.log")

            self.terminal_output.setFocus()

            pkey_obj = None
            if config.get("private_key"):
                key_file_obj = StringIO(config["private_key"])
                for key_class in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
                    try:
                        key_file_obj.seek(0)
                        pkey_obj = key_class.from_private_key(key_file_obj)
                        break
                    except paramiko.SSHException:
                        continue
                if not pkey_obj:
                    raise ValueError("Could not load private key.")

            self.ssh_client.connect(
                hostname=config["host"],
                port=config["port"],
                username=config["username"],
                password=config.get("password"),
                pkey=pkey_obj,
                timeout=10
            )

            self.shell_channel = self.ssh_client.invoke_shell(term='xterm-256color', width=120, height=30)
            self.shell_channel.settimeout(0.1)

            self.sftp_client = self.ssh_client.open_sftp()
            self.current_remote_path = self.sftp_client.normalize('.')

            self.read_worker = ShellReaderWorker(self.shell_channel, self.log_file_path)
            self.read_worker.output_received.connect(self._append_output)
            self.read_worker.finished.connect(self._on_disconnect)
            self.read_worker.start()

            self.status_label.setText(f"Connected to {config['username']}@{config['host']} | Path: {self.current_remote_path}")
            self.refresh_remote()

        except Exception as e:
            error_msg = f"Connection failed: {e}\n"
            self.terminal_output.write(error_msg)
            self.disconnect_ssh()

    def _append_output(self, text):
        self.session_log += text
        try:
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                f.write(text)
        except Exception:
            pass
        self.terminal_output.write(text)

    def _on_disconnect(self):
        self.disconnect_ssh()

    def disconnect_ssh(self):
        if self.read_worker:
            self.read_worker.stop()
            self.read_worker.wait()
            self.read_worker = None

        if self.ssh_client:
            try:
                if self.sftp_client:
                    self.sftp_client.close()
                self.ssh_client.close()
            except:
                pass

        self.ssh_client = None
        self.sftp_client = None
        self.shell_channel = None
        self.terminal_output.write("\r\n[Disconnected]\r\n")
        self.status_label.setText("Disconnected")

    def save_session_log(self):
        if not self.session_log.strip():
            QMessageBox.warning(self, "No Log", "There is no session output to save.")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Session Log",
            f"ssh_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.session_log)
                QMessageBox.information(self, "Saved", f"Session log saved to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save log:\n{e}")

    # ================== SFTP Methods ==================
    def refresh_remote(self):
        if not self.sftp_client:
            return
        try:
            self.remote_file_tree.clear()
            files = self.sftp_client.listdir_attr(self.current_remote_path)
            for attr in sorted(files, key=lambda x: (x.filename.startswith('.'), x.filename.lower())):
                name = attr.filename
                size = str(attr.st_size) if not (attr.st_mode & 0o170000 == 0o040000) else "<DIR>"
                mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(attr.st_mtime))
                item = QTreeWidgetItem([name, size, mtime])
                item.setData(0, Qt.ItemDataRole.UserRole, attr)
                self.remote_file_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.warning(self, "SFTP Error", f"Failed to list remote directory:\n{e}")

    def remote_item_double_clicked(self, item, column):
        if not self.sftp_client:
            return
        attr = item.data(0, Qt.ItemDataRole.UserRole)
        if attr.st_mode & 0o170000 == 0o040000:
            self.current_remote_path = os.path.normpath(os.path.join(self.current_remote_path, item.text(0)))
            self.refresh_remote()
            self.status_label.setText(f"Remote path: {self.current_remote_path}")
        else:
            self.preview_remote_file(item)

    def preview_remote_file(self, item):
        filename = item.text(0)
        remote_path = os.path.join(self.current_remote_path, filename)
        try:
            with self.sftp_client.open(remote_path, 'r') as f:
                content = f.read()
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='replace')
            dlg = TextPreviewDialog(filename, content, self)
            dlg.exec()
        except Exception as e:
            reply = QMessageBox.question(
                self, "Download?",
                f"Cannot preview '{filename}'.\nDownload instead?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.download_file(item)

    def remote_context_menu(self, position):
        if not self.sftp_client:
            return
        item = self.remote_file_tree.itemAt(position)
        if not item:
            return
        menu = QMenu()
        download_action = menu.addAction("Download")
        delete_action = menu.addAction("Delete")
        action = menu.exec(self.remote_file_tree.mapToGlobal(position))
        if action == download_action:
            self.download_file(item)
        elif action == delete_action:
            self.delete_remote_file(item)

    def upload_from_local(self):
        if not self.sftp_client:
            QMessageBox.warning(self, "Not Connected", "SFTP is not connected.")
            return
        indexes = self.local_file_tree.selectionModel().selectedIndexes()
        if not indexes:
            QMessageBox.warning(self, "No Selection", "Please select file(s) to upload.")
            return
        paths = set()
        for index in indexes:
            if index.column() == 0:
                path = self.local_model.filePath(index)
                if os.path.isfile(path):
                    paths.add(path)
        if not paths:
            QMessageBox.warning(self, "Invalid Selection", "Please select valid files.")
            return

        def do_upload():
            for local_path in paths:
                remote_path = os.path.join(self.current_remote_path, os.path.basename(local_path))
                try:
                    self.sftp_client.put(local_path, remote_path)
                except Exception as e:
                    print(f"Upload error: {e}")
                    return
            self.refresh_remote()
            self.terminal_output.write(f"[SFTP] Uploaded {len(paths)} file(s) to {self.current_remote_path}\r\n")

        worker = FileTransferWorker(do_upload)
        self.thread_pool.start(worker)

    def download_file(self, item):
        if not self.sftp_client:
            return
        attr = item.data(0, Qt.ItemDataRole.UserRole)
        if attr.st_mode & 0o170000 == 0o040000:
            QMessageBox.warning(self, "Directory", "Downloading directories is not supported.")
            return
        remote_name = item.text(0)
        remote_path = os.path.join(self.current_remote_path, remote_name)
        local_path, _ = QFileDialog.getSaveFileName(self, "Save File", remote_name)
        if not local_path:
            return

        def do_download():
            try:
                self.sftp_client.get(remote_path, local_path)
                self.terminal_output.write(f"[SFTP] Downloaded: {remote_name}\r\n")
            except Exception as e:
                print(f"Download error: {e}")

        worker = FileTransferWorker(do_download)
        self.thread_pool.start(worker)

    def delete_remote_file(self, item):
        attr = item.data(0, Qt.ItemDataRole.UserRole)
        name = item.text(0)
        is_dir = attr.st_mode & 0o170000 == 0o040000
        msg = f"Are you sure you want to delete {'directory' if is_dir else 'file'} '{name}'?"
        reply = QMessageBox.question(self, "Confirm Delete", msg, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            path = os.path.join(self.current_remote_path, name)

            def do_delete():
                try:
                    if is_dir:
                        self.sftp_client.rmdir(path)
                    else:
                        self.sftp_client.remove(path)
                    self.refresh_remote()
                except Exception as e:
                    print(f"Delete error: {e}")

            worker = FileTransferWorker(do_delete)
            self.thread_pool.start(worker)


# =============== SSH Connection Dialog ===============
class SshConnectDialog(QDialog):
    def __init__(self, parent=None, connection_data=None):
        super().__init__(parent)
        self.setWindowTitle("SSH Connection")
        self.setModal(True)
        self.connection_data = connection_data

        layout = QVBoxLayout(self)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Connection Name")
        layout.addWidget(self.name_input)

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Hostname or IP Address")
        layout.addWidget(self.host_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (default: 22)")
        self.port_input.setText("22")
        layout.addWidget(self.port_input)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        layout.addWidget(self.user_input)

        self.auth_method_tabs = QStackedWidget()
        self.password_widget = QWidget()
        password_layout = QVBoxLayout(self.password_widget)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Password")
        password_layout.addWidget(self.password_input)

        self.key_widget = QWidget()
        key_layout = QHBoxLayout(self.key_widget)
        self.key_path_input = QLineEdit()
        self.key_path_input.setPlaceholderText("Private Key Path")
        key_layout.addWidget(self.key_path_input)
        self.browse_key_button = QPushButton("Browse")
        self.browse_key_button.clicked.connect(self.browse_key)
        key_layout.addWidget(self.browse_key_button)

        self.auth_method_tabs.addWidget(self.password_widget)
        self.auth_method_tabs.addWidget(self.key_widget)

        self.auth_type_checkbox = QCheckBox("Use Private Key Authentication")
        self.auth_type_checkbox.toggled.connect(self.toggle_auth_method)
        layout.addWidget(self.auth_type_checkbox)
        layout.addWidget(self.auth_method_tabs)

        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        if self.connection_data:
            self.load_data()

    def toggle_auth_method(self, checked):
        self.auth_method_tabs.setCurrentIndex(1 if checked else 0)

    def browse_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Private Key")
        if file_path:
            self.key_path_input.setText(file_path)

    def load_data(self):
        self.name_input.setText(self.connection_data.get("name", ""))
        self.host_input.setText(self.connection_data.get("host", ""))
        self.port_input.setText(str(self.connection_data.get("port", "22")))
        self.user_input.setText(self.connection_data.get("username", ""))
        if self.connection_data.get("private_key"):
            self.auth_type_checkbox.setChecked(True)
            self.key_path_input.setText("[Key is already stored in database]")
        else:
            self.auth_type_checkbox.setChecked(False)
            self.password_input.setText(self.connection_data.get("password", ""))

    def get_data(self):
        data = {
            "name": self.name_input.text().strip(),
            "host": self.host_input.text().strip(),
            "port": int(self.port_input.text().strip() or 22),
            "username": self.user_input.text().strip(),
            "password": None,
            "private_key": None
        }

        if not all([data["name"], data["host"], data["username"]]):
            QMessageBox.warning(self, "Missing Information", "Connection Name, Host, and Username are required.")
            return None

        if self.auth_type_checkbox.isChecked():
            key_path = self.key_path_input.text()
            if self.connection_data and self.connection_data.get("private_key") and key_path == "[Key is already stored in database]":
                data["private_key"] = self.connection_data["private_key"]
            elif key_path and os.path.exists(key_path):
                try:
                    with open(key_path, 'r') as f:
                        data["private_key"] = f.read()
                except Exception as e:
                    QMessageBox.warning(self, "Error Reading File", f"Could not read the private key file: {e}")
                    return None
            elif key_path:
                QMessageBox.warning(self, "File Not Found", f"The specified key file does not exist: {key_path}")
                return None
            else:
                QMessageBox.warning(self, "Missing Key", "Please provide a path to a private key file.")
                return None
        else:
            data["password"] = self.password_input.text()
        return data