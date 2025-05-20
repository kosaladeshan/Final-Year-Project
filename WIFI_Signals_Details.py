import sys
import subprocess
import re
import json
import os
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QTableWidget, QTableWidgetItem, QPushButton, QProgressBar)
from PyQt6.QtGui import QPainter, QColor, QBrush, QPen, QFont, QLinearGradient
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, QThread, pyqtSignal, QPoint

class NetworkScannerThread(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            # Get connected network info
            connected_result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                           capture_output=True, text=True)
            connected_output = connected_result.stdout
            
            # Extract connected network's MAC address
            connected_mac = None
            for line in connected_output.splitlines():
                if "BSSID" in line and ":" in line:
                    mac_match = re.search(r'BSSID\s*:\s*(.+)', line)
                    if mac_match:
                        connected_mac = mac_match.group(1).strip().upper()
                        break
            
            # Get all networks
            result = subprocess.run(['netsh', 'wlan', 'show', 'network', 'mode=bssid'], 
                                  capture_output=True, text=True)
            output = result.stdout
            
            networks = []
            current_ssid = None
            current_bssid = None
            current_signal = None
            current_channel = None
            current_freq = None
            current_auth = None
            current_radio_type = None
            current_network_type = None
            current_network_mode = None
            
            for line in output.splitlines():
                if "SSID" in line and ":" in line and not "BSSID" in line:
                    ssid_match = re.search(r'SSID\s*\d*\s*:\s*(.+)', line)
                    if ssid_match:
                        current_ssid = ssid_match.group(1).strip()
                        current_bssid = None
                        current_signal = None
                        current_auth = None
                        current_channel = None
                        current_freq = None
                        current_radio_type = None
                        current_network_type = None
                        current_network_mode = None
                
                elif "Authentication" in line:
                    auth_match = re.search(r':\s*(.+)', line)
                    if auth_match:
                        current_auth = auth_match.group(1).strip()
                
                elif "BSSID" in line and ":" in line:
                    bssid_match = re.search(r'BSSID\s*\d*\s*:\s*(.+)', line)
                    if bssid_match:
                        current_bssid = bssid_match.group(1).strip().upper()
                
                elif "Signal" in line:
                    signal_match = re.search(r':\s*(\d+)%', line)
                    if signal_match:
                        current_signal = signal_match.group(1) + "%"
                
                elif "Channel" in line:
                    channel_match = re.search(r':\s*(\d+)', line)
                    if channel_match:
                        current_channel = channel_match.group(1)
                        
                        # Calculate frequency and network type based on channel
                        if int(current_channel) <= 14:  # 2.4GHz
                            current_freq = f"{2412 + (int(current_channel) - 1) * 5} MHz"
                            current_network_type = "2.4 GHz"
                        else:  # 5GHz
                            if int(current_channel) >= 36:
                                current_freq = f"{5180 + ((int(current_channel) - 36) * 5)} MHz"
                                current_network_type = "5 GHz"
                            else:
                                current_freq = "Unknown MHz"
                                current_network_type = "Unknown"
                
                elif "Radio type" in line:
                    radio_match = re.search(r':\s*(.+)', line)
                    if radio_match:
                        current_radio_type = radio_match.group(1).strip()
                
                elif "Network type" in line:
                    network_type_match = re.search(r':\s*(.+)', line)
                    if network_type_match:
                        current_network_mode = network_type_match.group(1).strip()
                
                # Add network when we have all required info
                if current_ssid and current_bssid and current_signal and current_channel and current_auth:
                    # Convert signal to dBm (estimate)
                    signal_percentage = int(current_signal.strip('%'))
                    signal_dbm = percentage_to_dbm(signal_percentage)
                    signal_str = f"{signal_dbm} dBm"
                    
                    # Check if network already exists, if not add it
                    existing = False
                    for i, net in enumerate(networks):
                        if net[2] == current_bssid:  # Check BSSID
                            existing = True
                            networks[i] = [current_ssid, signal_str, current_bssid, 
                                         current_auth, current_channel, current_freq,
                                         current_network_type, current_radio_type, current_network_mode,
                                         "Connected" if current_bssid == connected_mac else ""]
                            break
                    
                    if not existing:
                        networks.append([current_ssid, signal_str, current_bssid, 
                                       current_auth, current_channel, current_freq,
                                       current_network_type, current_radio_type, current_network_mode,
                                       "Connected" if current_bssid == connected_mac else ""])
                    
                    # Reset for next network
                    current_bssid = None
                    current_signal = None
                    current_channel = None
                    current_freq = None
                    current_radio_type = None
                    current_network_type = None
                    current_network_mode = None
            
            self.finished.emit(networks)
            
        except Exception as e:
            self.error.emit(str(e))

def percentage_to_dbm(percentage):
    # More accurate conversion based on common WiFi ranges
    if percentage >= 100:
        return -50
    elif percentage <= 0:
        return -100
    return int(-100 + ((percentage * 50) / 100))

class SignalStrengthWidget(QWidget):
    def __init__(self, parent=None, dBm=-50):
        super().__init__(parent)
        self.dBm = dBm
        self.setMinimumWidth(150)
        self.setFixedHeight(15)
    
    def setDbm(self, dBm):
        self.dBm = dBm
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Create gradient
        gradient = QLinearGradient(0, 0, self.width(), 0)
        gradient.setColorAt(0, QColor(255, 0, 0))        # Red (weak)
        gradient.setColorAt(0.5, QColor(255, 0, 255))    # Purple (medium)
        gradient.setColorAt(1, QColor(0, 0, 255))        # Blue (strong)
        
        # Calculate width based on signal strength
        # Assume -100 dBm is 0% and -30 dBm is 100%
        signal_strength = max(0, min(100, (self.dBm + 100) * 100 / 70))
        width = int(self.width() * signal_strength / 100)
        
        # Draw background
        painter.fillRect(0, 0, self.width(), self.height(), QColor(30, 30, 40))
        
        # Draw signal bar
        painter.fillRect(0, 0, width, self.height(), gradient)

class WifiNetworkChart(QWidget):
    def __init__(self):
        super().__init__()
        self.networks = []
        self.setMinimumHeight(300)
        
    def update_networks(self, networks):
        self.networks = networks
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor(30, 30, 40))
        
        # Grid lines and percentages
        painter.setPen(QPen(QColor(80, 80, 80, 100), 1))
        font = QFont()
        font.setPointSize(8)
        painter.setFont(font)
        
        # Draw horizontal grid lines
        for i in range(0, 101, 10):
            y = int(self.height() - (i / 100 * self.height()))
            painter.drawLine(0, y, self.width(), y)
            painter.drawText(5, y - 5, f"{i}%")
        
        # Draw vertical grid lines for channels
        width = self.width() - 20
        for i in range(0, 201, 25):
            x = 10 + i * width / 200
            painter.drawLine(int(x), 0, int(x), self.height() - 20)
            painter.drawText(int(x - 10), self.height() - 5, 20, 20, 
                           Qt.AlignmentFlag.AlignCenter, str(i))
        
        # Draw networks as colored areas
        if self.networks:
            # Group networks by channel to identify same-channel networks
            networks_by_channel = {}
            for network in self.networks:
                if not network[4].isdigit():
                    continue
                channel = int(network[4])
                if channel not in networks_by_channel:
                    networks_by_channel[channel] = []
                networks_by_channel[channel].append(network)
            
            # Define unique colors for different channels
            colors = {
                1: QColor(255, 100, 100, 150),    # Red-ish
                11: QColor(255, 0, 255, 150),     # Magenta
                6: QColor(100, 255, 100, 150),    # Green-ish
                36: QColor(100, 100, 255, 150),   # Blue-ish
                44: QColor(255, 255, 0, 150),     # Yellow
                149: QColor(0, 255, 255, 150),    # Cyan
            }
            
            default_color = QColor(200, 200, 200, 150)  # Default gray for other channels
            
            # Draw each network
            for channel, nets in networks_by_channel.items():
                # Choose color based on channel or use default
                color = colors.get(channel, default_color)
                
                # Find x-coordinate based on channel (scale to fit)
                if channel <= 14:  # 2.4GHz
                    x_center = 10 + (channel * 10) * width / 200
                else:  # 5GHz - scale differently
                    x_center = 10 + (100 + (channel - 36) * 0.5) * width / 200
                
                for net in nets:
                    # Get signal strength in percentage
                    signal_text = net[1].replace(" dBm", "")
                    signal_dbm = int(signal_text)
                    signal_percentage = min(100, max(0, (signal_dbm + 100) * 100 / 70))
                    
                    # Draw a bell curve representation
                    curve_width = width / 20
                    points = []
                    
                    for x in range(int(x_center - curve_width), int(x_center + curve_width) + 1, 5):
                        # Calculate bell curve
                        distance = (x - x_center) / curve_width
                        y_factor = max(0, 1 - (distance * distance))
                        y = self.height() - (signal_percentage * y_factor * self.height() / 100)
                        points.append((x, y))
                    
                    if points:
                        # Create polygon for filling
                        path_points = [points[0]]
                        path_points.extend(points)
                        path_points.append((points[-1][0], self.height()))
                        path_points.append((points[0][0], self.height()))
                        
                        # Fill with semi-transparent color
                        painter.setBrush(color)
                        painter.setPen(Qt.PenStyle.NoPen)
                        painter.drawPolygon([QPoint(x, int(y)) for x, y in path_points])
                        
                        # Draw outline
                        painter.setPen(QPen(color.darker(150), 2))
                        for i in range(len(points) - 1):
                            painter.drawLine(
                                int(points[i][0]), int(points[i][1]), 
                                int(points[i+1][0]), int(points[i+1][1])
                            )
                        
                        # Draw network name
                        painter.setPen(Qt.GlobalColor.white)
                        text_rect = QRect(
                            int(x_center - 80), 
                            int(self.height() * (1 - signal_percentage/100) - 20),
                            160, 20
                        )
                        painter.drawText(
                            text_rect,
                            Qt.AlignmentFlag.AlignCenter,
                            f"*{net[0]}*"
                        )

class LoadingBarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(200, 30)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_bar.setStyleSheet("background-color: rgba(50, 50, 50, 200); border: none;")
        
        layout = QVBoxLayout(self)
        layout.addWidget(self.progress_bar)
        self.setLayout(layout)
        
        self.anim = QPropertyAnimation(self.progress_bar, b"value")
        self.anim.setStartValue(0)
        self.anim.setEndValue(100)
        self.anim.setDuration(2000)  # Increase duration for smoother animation
        self.anim.setLoopCount(-1)  # Loop indefinitely
        self.anim.setEasingCurve(QEasingCurve.Type.Linear)  # Use linear easing for smoothness

    def start_animation(self):
        self.anim.start()

    def stop_animation(self):
        self.anim.stop()

class WifiScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wi-Fi Scanner")
        self.setMinimumSize(1300, 600)  # Increased width to accommodate new column
        self.scanning = False
        
        # Define the JSON file path
        self.json_file_path = os.path.join("data_temp", "wifi_signals_details.json")
        
        # Ensure the data_temp directory exists
        os.makedirs(os.path.dirname(self.json_file_path), exist_ok=True)
        
        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Table widget with additional columns
        self.table = QTableWidget()
        self.table.setColumnCount(10)  # Increased number of columns
        self.table.setHorizontalHeaderLabels([
            "SSID", "Signal", "BSSID", "Security", 
            "Channel", "Frequency", "Network Type", 
            "Radio Type", "Network Mode", "Connection Status"
        ])
        main_layout.addWidget(self.table)
        
        # Chart widget
        self.chart = WifiNetworkChart()
        main_layout.addWidget(self.chart)
        
        # Loading bar widget
        self.loading_bar = LoadingBarWidget(self)
        self.loading_bar.move(self.width() - self.loading_bar.width() - 20, self.height() - self.loading_bar.height() - 20)
        self.loading_bar.hide()
        
        # Button for scanning
        button_layout = QHBoxLayout()
        scan_button = QPushButton("Scan Wi-Fi Networks")
        scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(scan_button)
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        # Scanner thread
        self.scanner_thread = NetworkScannerThread()
        self.scanner_thread.finished.connect(self.on_scan_finished)
        self.scanner_thread.error.connect(self.on_scan_error)
        
        # Set up timer for auto refresh
        self.timer = QTimer()
        self.timer.timeout.connect(self.start_scan)
        self.timer.start(10000)  # Refresh every 10 seconds
        
        # Initial scan
        self.start_scan()
        
    def resizeEvent(self, event):
        # Resize the loading bar to match the window size
        self.loading_bar.move(self.width() - self.loading_bar.width() - 20, self.height() - self.loading_bar.height() - 20)
        super().resizeEvent(event)
    
    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.show_loading_bar()
            self.status_label.setText("Scanning...")
            self.scanner_thread.start()
    
    def show_loading_bar(self):
        self.loading_bar.show()
        self.loading_bar.start_animation()
    
    def hide_loading_bar(self):
        self.loading_bar.hide()
        self.loading_bar.stop_animation()
    
    def on_scan_finished(self, networks):
        self.hide_loading_bar()
        self.scanning = False
        
        # Update table
        self.table.setRowCount(len(networks))
        for row, network in enumerate(networks):
            for col, value in enumerate(network):
                if col == 1:  # Signal strength column
                    # Create signal bar widget for this column
                    cell_widget = QWidget()
                    layout = QHBoxLayout(cell_widget)
                    layout.setContentsMargins(4, 2, 4, 2)
                    
                    label = QLabel(value)
                    signal_bar = SignalStrengthWidget()
                    dBm = int(value.split(" ")[0])
                    signal_bar.setDbm(dBm)
                    
                    layout.addWidget(label)
                    layout.addWidget(signal_bar)
                    self.table.setCellWidget(row, col, cell_widget)
                else:
                    item = QTableWidgetItem(str(value))
                    if col == 0:  # SSID column - align left
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    else:  # Other columns - align center
                        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
                    self.table.setItem(row, col, item)
        
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)
        
        # Update chart
        self.chart.update_networks(networks)
        
        # Update status
        self.status_label.setText(f"Found {len(networks)} networks")
        
        # Save data to JSON file
        self.save_to_json(networks)
    
    def on_scan_error(self, error_msg):
        self.hide_loading_bar()
        self.scanning = False
        self.status_label.setText(f"Error: {error_msg}")
    
    def save_to_json(self, networks):
        try:
            # Convert networks data to a list of dictionaries
            networks_data = []
            for network in networks:
                network_dict = {
                    "SSID": network[0],
                    "Signal": network[1],
                    "BSSID": network[2],
                    "Security": network[3],
                    "Channel": network[4],
                    "Frequency": network[5],
                    "Network Type": network[6],
                    "Radio Type": network[7],
                    "Network Mode": network[8],
                    "Connection Status": network[9],
                    "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                networks_data.append(network_dict)
            
            # Save to JSON file
            with open(self.json_file_path, 'w') as f:
                json.dump(networks_data, f, indent=4)
                
        except Exception as e:
            print(f"Error saving to JSON file: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for consistent look across platforms
    
    # Set dark theme
    palette = app.palette()
    palette.setColor(palette.ColorRole.Window, QColor(35, 35, 45))
    palette.setColor(palette.ColorRole.WindowText, QColor(200, 200, 200))
    palette.setColor(palette.ColorRole.Base, QColor(25, 25, 35))
    palette.setColor(palette.ColorRole.AlternateBase, QColor(35, 35, 45))
    palette.setColor(palette.ColorRole.Text, QColor(200, 200, 200))
    palette.setColor(palette.ColorRole.Button, QColor(35, 35, 45))
    palette.setColor(palette.ColorRole.ButtonText, QColor(200, 200, 200))
    palette.setColor(palette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(palette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(palette.ColorRole.HighlightedText, QColor(200, 200, 200))
    app.setPalette(palette)
    
    window = WifiScannerApp()
    window.show()
    sys.exit(app.exec())
