import subprocess
import json
import time
import os
import shutil
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QHBoxLayout, QFrame, QMessageBox, QLineEdit, QFormLayout
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
import pyqtgraph as pg


# مسیر ذخیره تاریخچه
HISTORY_FILE = Path.home() / ".zurvan_speedtest_history.json"


class SpeedTestThread(QThread):
    result_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, server_id=None):
        super().__init__()
        self.server_id = server_id

    def _available_speedtest_commands(self):
        commands = []

        official = shutil.which("speedtest")
        if official:
            cmd = [official, "--accept-license", "--accept-gdpr", "--format=json-pretty"]
            if self.server_id:
                cmd.extend(["--server-id", str(self.server_id)])
            commands.append((cmd, "ookla"))

            legacy_cmd = [official, "--json"]
            if self.server_id:
                legacy_cmd.extend(["--server", str(self.server_id)])
            commands.append((legacy_cmd, "legacy"))

        legacy = shutil.which("speedtest-cli")
        if legacy:
            cmd = [legacy, "--json"]
            if self.server_id:
                cmd.extend(["--server", str(self.server_id)])
            commands.append((cmd, "legacy"))

        return commands

    def _normalize_speedtest_result(self, data):
        # Official Ookla CLI schema.
        if isinstance(data.get("download"), dict):
            server = data.get("server", {})
            ping = data.get("ping", {})
            download = data.get("download", {})
            upload = data.get("upload", {})
            interface = data.get("interface", {})

            distance_km = server.get("distance")
            if distance_km is None:
                distance_km = "N/A"
            else:
                distance_km = round(distance_km, 2)

            return {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "public_ip": interface.get("externalIp", "N/A"),
                "server_id": server.get("id", "N/A"),
                "server_name": server.get("name", "N/A"),
                "server_country": server.get("country", "N/A"),
                "server_location": server.get("location", "N/A"),
                "distance_km": distance_km,
                "ping_ms": round(ping.get("latency", 0), 2),
                "jitter_ms": round(ping.get("jitter", 0), 2),
                "download_mbps": round(download.get("bandwidth", 0) * 8 / 1_000_000, 2),
                "upload_mbps": round(upload.get("bandwidth", 0) * 8 / 1_000_000, 2),
            }

        # Legacy speedtest-cli JSON schema.
        server = data.get("server", {})
        client = data.get("client", {})
        ping_ms = data.get("ping", 0)

        distance_km = server.get("d", "N/A")
        try:
            distance_km = round(float(distance_km), 2)
        except (TypeError, ValueError):
            distance_km = "N/A"

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "public_ip": client.get("ip", "N/A"),
            "server_id": server.get("id", "N/A"),
            "server_name": server.get("sponsor", server.get("name", "N/A")),
            "server_country": server.get("country", "N/A"),
            "server_location": server.get("name", "N/A"),
            "distance_km": distance_km,
            "ping_ms": round(float(ping_ms or 0), 2),
            "jitter_ms": "N/A",
            "download_mbps": round(float(data.get("download", 0)) / 1_000_000, 2),
            "upload_mbps": round(float(data.get("upload", 0)) / 1_000_000, 2),
        }

    def run(self):
        try:
            result = None
            last_error = ""
            for cmd, _mode in self._available_speedtest_commands():
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    break
                last_error = (result.stderr or result.stdout or "").strip()
            else:
                install_hint = (
                    "Install Ookla Speedtest CLI or make sure 'speedtest' is available in PATH.\n"
                    "macOS: brew install speedtest-cli\n"
                    "Linux: install the official Speedtest CLI package or a distro package that provides 'speedtest'."
                )
                self.error_occurred.emit(f"Speedtest failed or is not installed.\n{install_hint}\n\n{last_error}".strip())
                return

            data = json.loads(result.stdout)
            res = self._normalize_speedtest_result(data)
            self.result_ready.emit(res)

        except subprocess.TimeoutExpired:
            self.error_occurred.emit("⏱️ Speedtest timed out (120s).")
        except json.JSONDecodeError:
            self.error_occurred.emit("❌ Invalid JSON from speedtest.")
        except KeyError as e:
            self.error_occurred.emit(f"❌ Missing field in output: {str(e)}")
        except Exception as e:
            self.error_occurred.emit(f"💥 Unexpected error:\n{str(e)}")
        finally:
            self.finished.emit()


class SpeedTestTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.history_data = []
        self.load_history()
        self.init_ui()
        self.update_history_table()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Server ID input
        server_form = QFormLayout()
        self.server_id_input = QLineEdit()
        self.server_id_input.setPlaceholderText("Leave empty for best server")
        server_form.addRow("Server ID (optional):", self.server_id_input)
        layout.addLayout(server_form)

        # Start button
        self.start_btn = QPushButton("🚀 Start Speed Test")
        self.start_btn.clicked.connect(self.start_test)
        layout.addWidget(self.start_btn)

        # Results
        self.ip_label = QLabel("Public IP: —")
        self.server_label = QLabel("Server: —")
        self.ping_label = QLabel("Ping: —")
        self.dl_label = QLabel("Download: —")
        self.ul_label = QLabel("Upload: —")
        for lbl in [self.ip_label, self.server_label, self.ping_label, self.dl_label, self.ul_label]:
            layout.addWidget(lbl)

        # Graphs
        graph_layout = QHBoxLayout()
        self.dl_graph = pg.PlotWidget(title="⬇️ Download")
        self.ul_graph = pg.PlotWidget(title="⬆️ Upload")
        for g in (self.dl_graph, self.ul_graph):
            g.setBackground('w')
            g.showGrid(x=True, y=True)
            g.setLabel('left', 'Mbps')
            g.setXRange(0, 1)
            g.setYRange(0, 100)
        graph_layout.addWidget(self.dl_graph)
        graph_layout.addWidget(self.ul_graph)
        layout.addLayout(graph_layout)

        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(10)
        self.history_table.setHorizontalHeaderLabels([
            "Time", "IP", "Server ID", "Name", "Location", "Distance (km)",
            "Ping (ms)", "Jitter", "Download", "Upload"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.history_table)

    def start_test(self):
        server_id = self.server_id_input.text().strip()
        if server_id and not server_id.isdigit():
            QMessageBox.warning(self, "Invalid Input", "Server ID must be a number or empty.")
            return

        self.start_btn.setEnabled(False)
        self.reset_labels()

        self.dl_graph.clear()
        self.ul_graph.clear()

        self.thread = SpeedTestThread(server_id=int(server_id) if server_id else None)
        self.thread.result_ready.connect(self.on_result)
        self.thread.error_occurred.connect(self.on_error)
        self.thread.finished.connect(lambda: self.start_btn.setEnabled(True))
        self.thread.start()

    def reset_labels(self):
        self.ip_label.setText("Public IP: Testing...")
        self.server_label.setText("Server: Connecting...")
        self.ping_label.setText("Ping: Testing...")
        self.dl_label.setText("Download: Testing...")
        self.ul_label.setText("Upload: Testing...")

    def on_result(self, res):
        self.ip_label.setText(f"Public IP: {res['public_ip']}")
        self.server_label.setText(f"Server: {res['server_name']} ({res['server_country']}) [ID: {res['server_id']}]")
        jitter = res['jitter_ms']
        jitter_text = f"{jitter} ms" if jitter != "N/A" else "N/A"
        self.ping_label.setText(f"Ping: {res['ping_ms']} ms (Jitter: {jitter_text})")
        self.dl_label.setText(f"Download: {res['download_mbps']} Mbps")
        self.ul_label.setText(f"Upload: {res['upload_mbps']} Mbps")

        self.dl_graph.plot([0.5], [res['download_mbps']], pen=None, symbol='o', symbolSize=15, symbolBrush='b')
        self.ul_graph.plot([0.5], [res['upload_mbps']], pen=None, symbol='o', symbolSize=15, symbolBrush='g')

        # ذخیره در تاریخچه
        self.history_data.append(res)
        self.save_history()
        self.update_history_table()

    def on_error(self, msg):
        QMessageBox.critical(self, "Speed Test Error", msg)
        self.reset_labels()

    def load_history(self):
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    self.history_data = json.load(f)
            except Exception:
                self.history_data = []

    def save_history(self):
        try:
            HISTORY_FILE.parent.mkdir(exist_ok=True)
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.history_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Failed to save history: {e}")

    def update_history_table(self):
        self.history_table.setRowCount(len(self.history_data))
        for row, item in enumerate(self.history_data):
            self.history_table.setItem(row, 0, QTableWidgetItem(item["timestamp"]))
            self.history_table.setItem(row, 1, QTableWidgetItem(item["public_ip"]))
            self.history_table.setItem(row, 2, QTableWidgetItem(str(item["server_id"])))
            self.history_table.setItem(row, 3, QTableWidgetItem(item["server_name"]))
            self.history_table.setItem(row, 4, QTableWidgetItem(f"{item['server_location']}, {item['server_country']}"))
            self.history_table.setItem(row, 5, QTableWidgetItem(str(item["distance_km"])))
            self.history_table.setItem(row, 6, QTableWidgetItem(str(item["ping_ms"])))
            self.history_table.setItem(row, 7, QTableWidgetItem(str(item["jitter_ms"])))
            self.history_table.setItem(row, 8, QTableWidgetItem(str(item["download_mbps"])))
            self.history_table.setItem(row, 9, QTableWidgetItem(str(item["upload_mbps"])))
