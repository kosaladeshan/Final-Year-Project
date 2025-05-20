import sys
import time
import threading
import os
import json
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np

def create_manuf_file():
    """Create a basic manuf file with common MAC address prefixes"""
    manuf_content = """# Wireshark manufacturer database
# This is a simplified version for basic MAC address lookup
# Format: MAC_PREFIX\tMANUFACTURER_NAME

00:00:0C	Cisco
00:00:0E	Fujitsu
00:00:1B	Novell
00:00:1D	Cabletron
00:00:1E	Fujitsu
00:00:1F	Fujitsu
00:00:20	Fujitsu
00:00:21	Fujitsu
00:00:22	Fujitsu
00:00:23	Fujitsu
00:00:24	Fujitsu
00:00:25	Fujitsu
00:00:26	Fujitsu
00:00:27	Fujitsu
00:00:28	Fujitsu
00:00:29	Fujitsu
00:00:2A	Fujitsu
00:00:2B	Fujitsu
00:00:2C	Fujitsu
00:00:2D	Fujitsu
00:00:2E	Fujitsu
00:00:2F	Fujitsu
00:00:30	Fujitsu
00:00:31	Fujitsu
00:00:32	Fujitsu
00:00:33	Fujitsu
00:00:34	Fujitsu
00:00:35	Fujitsu
00:00:36	Fujitsu
00:00:37	Fujitsu
00:00:38	Fujitsu
00:00:39	Fujitsu
00:00:3A	Fujitsu
00:00:3B	Fujitsu
00:00:3C	Fujitsu
00:00:3D	Fujitsu
00:00:3E	Fujitsu
00:00:3F	Fujitsu
00:00:40	Fujitsu
00:00:41	Fujitsu
00:00:42	Fujitsu
00:00:43	Fujitsu
00:00:44	Fujitsu
00:00:45	Fujitsu
00:00:46	Fujitsu
00:00:47	Fujitsu
00:00:48	Fujitsu
00:00:49	Fujitsu
00:00:4A	Fujitsu
00:00:4B	Fujitsu
00:00:4C	Fujitsu
00:00:4D	Fujitsu
00:00:4E	Fujitsu
00:00:4F	Fujitsu
00:00:50	Fujitsu
00:00:51	Fujitsu
00:00:52	Fujitsu
00:00:53	Fujitsu
00:00:54	Fujitsu
00:00:55	Fujitsu
00:00:56	Fujitsu
00:00:57	Fujitsu
00:00:58	Fujitsu
00:00:59	Fujitsu
00:00:5A	Fujitsu
00:00:5B	Fujitsu
00:00:5C	Fujitsu
00:00:5D	Fujitsu
00:00:5E	Fujitsu
00:00:5F	Fujitsu
00:00:60	Fujitsu
00:00:61	Fujitsu
00:00:62	Fujitsu
00:00:63	Fujitsu
00:00:64	Fujitsu
00:00:65	Fujitsu
00:00:66	Fujitsu
00:00:67	Fujitsu
00:00:68	Fujitsu
00:00:69	Fujitsu
00:00:6A	Fujitsu
00:00:6B	Fujitsu
00:00:6C	Fujitsu
00:00:6D	Fujitsu
00:00:6E	Fujitsu
00:00:6F	Fujitsu
00:00:70	Fujitsu
00:00:71	Fujitsu
00:00:72	Fujitsu
00:00:73	Fujitsu
00:00:74	Fujitsu
00:00:75	Fujitsu
00:00:76	Fujitsu
00:00:77	Fujitsu
00:00:78	Fujitsu
00:00:79	Fujitsu
00:00:7A	Fujitsu
00:00:7B	Fujitsu
00:00:7C	Fujitsu
00:00:7D	Fujitsu
00:00:7E	Fujitsu
00:00:7F	Fujitsu
00:00:80	Fujitsu
00:00:81	Fujitsu
00:00:82	Fujitsu
00:00:83	Fujitsu
00:00:84	Fujitsu
00:00:85	Fujitsu
00:00:86	Fujitsu
00:00:87	Fujitsu
00:00:88	Fujitsu
00:00:89	Fujitsu
00:00:8A	Fujitsu
00:00:8B	Fujitsu
00:00:8C	Fujitsu
00:00:8D	Fujitsu
00:00:8E	Fujitsu
00:00:8F	Fujitsu
00:00:90	Fujitsu
00:00:91	Fujitsu
00:00:92	Fujitsu
00:00:93	Fujitsu
00:00:94	Fujitsu
00:00:95	Fujitsu
00:00:96	Fujitsu
00:00:97	Fujitsu
00:00:98	Fujitsu
00:00:99	Fujitsu
00:00:9A	Fujitsu
00:00:9B	Fujitsu
00:00:9C	Fujitsu
00:00:9D	Fujitsu
00:00:9E	Fujitsu
00:00:9F	Fujitsu
00:00:A0	Fujitsu
00:00:A1	Fujitsu
00:00:A2	Fujitsu
00:00:A3	Fujitsu
00:00:A4	Fujitsu
00:00:A5	Fujitsu
00:00:A6	Fujitsu
00:00:A7	Fujitsu
00:00:A8	Fujitsu
00:00:A9	Fujitsu
00:00:AA	Fujitsu
00:00:AB	Fujitsu
00:00:AC	Fujitsu
00:00:AD	Fujitsu
00:00:AE	Fujitsu
00:00:AF	Fujitsu
00:00:B0	Fujitsu
00:00:B1	Fujitsu
00:00:B2	Fujitsu
00:00:B3	Fujitsu
00:00:B4	Fujitsu
00:00:B5	Fujitsu
00:00:B6	Fujitsu
00:00:B7	Fujitsu
00:00:B8	Fujitsu
00:00:B9	Fujitsu
00:00:BA	Fujitsu
00:00:BB	Fujitsu
00:00:BC	Fujitsu
00:00:BD	Fujitsu
00:00:BE	Fujitsu
00:00:BF	Fujitsu
00:00:C0	Fujitsu
00:00:C1	Fujitsu
00:00:C2	Fujitsu
00:00:C3	Fujitsu
00:00:C4	Fujitsu
00:00:C5	Fujitsu
00:00:C6	Fujitsu
00:00:C7	Fujitsu
00:00:C8	Fujitsu
00:00:C9	Fujitsu
00:00:CA	Fujitsu
00:00:CB	Fujitsu
00:00:CC	Fujitsu
00:00:CD	Fujitsu
00:00:CE	Fujitsu
00:00:CF	Fujitsu
00:00:D0	Fujitsu
00:00:D1	Fujitsu
00:00:D2	Fujitsu
00:00:D3	Fujitsu
00:00:D4	Fujitsu
00:00:D5	Fujitsu
00:00:D6	Fujitsu
00:00:D7	Fujitsu
00:00:D8	Fujitsu
00:00:D9	Fujitsu
00:00:DA	Fujitsu
00:00:DB	Fujitsu
00:00:DC	Fujitsu
00:00:DD	Fujitsu
00:00:DE	Fujitsu
00:00:DF	Fujitsu
00:00:E0	Fujitsu
00:00:E1	Fujitsu
00:00:E2	Fujitsu
00:00:E3	Fujitsu
00:00:E4	Fujitsu
00:00:E5	Fujitsu
00:00:E6	Fujitsu
00:00:E7	Fujitsu
00:00:E8	Fujitsu
00:00:E9	Fujitsu
00:00:EA	Fujitsu
00:00:EB	Fujitsu
00:00:EC	Fujitsu
00:00:ED	Fujitsu
00:00:EE	Fujitsu
00:00:EF	Fujitsu
00:00:F0	Fujitsu
00:00:F1	Fujitsu
00:00:F2	Fujitsu
00:00:F3	Fujitsu
00:00:F4	Fujitsu
00:00:F5	Fujitsu
00:00:F6	Fujitsu
00:00:F7	Fujitsu
00:00:F8	Fujitsu
00:00:F9	Fujitsu
00:00:FA	Fujitsu
00:00:FB	Fujitsu
00:00:FC	Fujitsu
00:00:FD	Fujitsu
00:00:FE	Fujitsu
00:00:FF	Fujitsu
"""
    manuf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manuf", "manuf")
    os.makedirs(os.path.dirname(manuf_path), exist_ok=True)

    if not os.path.exists(manuf_path):
        with open(manuf_path, 'w') as f:
            f.write(manuf_content)

    return manuf_path

# Create manuf file if it doesn't exist
manuf_path = create_manuf_file()
os.environ["WIRESHARK_MANUF_PATH"] = manuf_path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                            QWidget, QComboBox, QPushButton, QTableWidget,
                            QTableWidgetItem, QLabel, QTabWidget, QTextEdit,
                            QGroupBox, QCheckBox, QLineEdit, QMessageBox,
                            QGridLayout, QHeaderView, QFileDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont, QPalette

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.packet import Raw

class PacketStats:
    def __init__(self):
        self.total_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.other_packets = 0
        self.total_bytes = 0
        self.tcp_bytes = 0
        self.udp_bytes = 0
        self.icmp_bytes = 0
        self.other_bytes = 0
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.dest_ips = defaultdict(int)
        self.packet_sizes = []
        self.start_time = time.time()
        self.data_dir = 'data_temp'
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.packets_data = []
        self.json_file = os.path.join(self.data_dir, 'real_time_packet.json')

    def get_protocol_name(self, packet):
        """Helper method to determine protocol name"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return 'Unknown'

    def get_packet_info(self, packet):
        """Helper method to get packet info"""
        if TCP in packet:
            return f"Port {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            return f"Port {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            return f"Type: {packet[ICMP].type}"
        return ''

    def update(self, packet):
        self.total_packets += 1
        packet_size = len(packet)
        self.total_bytes += packet_size

        if IP in packet:
            self.ip_stats[packet[IP].src] += 1
            self.ip_stats[packet[IP].dst] += 1

        if TCP in packet:
            self.tcp_packets += 1
            self.tcp_bytes += packet_size
            self.protocol_stats['TCP'] += 1
            self.port_stats[f"TCP:{packet[TCP].sport}"] += 1
            self.port_stats[f"TCP:{packet[TCP].dport}"] += 1
        elif UDP in packet:
            self.udp_packets += 1
            self.udp_bytes += packet_size
            self.protocol_stats['UDP'] += 1
            self.port_stats[f"UDP:{packet[UDP].sport}"] += 1
            self.port_stats[f"UDP:{packet[UDP].dport}"] += 1
        elif ICMP in packet:
            self.icmp_packets += 1
            self.icmp_bytes += packet_size
            self.protocol_stats['ICMP'] += 1
        else:
            self.other_packets += 1
            self.other_bytes += packet_size
            self.protocol_stats['Other'] += 1

        # Store packet data
        packet_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': packet[IP].src if IP in packet else 'Unknown',
            'dest_ip': packet[IP].dst if IP in packet else 'Unknown',
            'protocol': self.get_protocol_name(packet),
            'length': packet_size,
            'info': self.get_packet_info(packet)
        }
        self.packets_data.append(packet_data)

        # Save to JSON every 100 packets
        if len(self.packets_data) % 100 == 0:
            self.save_to_json()

    def get_percentages(self):
        total = self.total_packets
        if total == 0:
            return {
                'TCP': 0,
                'UDP': 0,
                'ICMP': 0,
                'Other': 0
            }
        return {
            'TCP': (self.tcp_packets / total) * 100,
            'UDP': (self.udp_packets / total) * 100,
            'ICMP': (self.icmp_packets / total) * 100,
            'Other': (self.other_packets / total) * 100
        }

    def save_to_json(self):
        try:
            # Save all data to real_time_packet.json
            data = {
                'packets': self.packets_data,
                'statistics': {
                    'total_packets': self.total_packets,
                    'tcp_packets': self.tcp_packets,
                    'udp_packets': self.udp_packets,
                    'icmp_packets': self.icmp_packets,
                    'other_packets': self.other_packets,
                    'total_bytes': self.total_bytes,
                    'tcp_bytes': self.tcp_bytes,
                    'udp_bytes': self.udp_bytes,
                    'icmp_bytes': self.icmp_bytes,
                    'other_bytes': self.other_bytes,
                    'protocol_stats': dict(self.protocol_stats),
                    'port_stats': dict(self.port_stats),
                    'ip_stats': dict(self.ip_stats),
                    'capture_duration': time.time() - self.start_time,
                    'capture_end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            }

            with open(self.json_file, 'w') as f:
                json.dump(data, f, indent=4)

            print(f"Data saved to {self.json_file}")
        except Exception as e:
            print(f"Error saving to JSON: {str(e)}")

class PacketCaptureWorker(QObject):
    packet_captured = pyqtSignal(scapy.packet.Packet)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.is_running = False

    def start_capture(self):
        self.is_running = True
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_captured.emit,
                       store=False, stop_filter=lambda _: not self.is_running)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop_capture(self):
        self.is_running = False

class PacketAnalyzer(QMainWindow):
    dataReady = pyqtSignal(dict)  # Signal to send data to report generator

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Packet Analyzer")
        
        # Set initial window position and size (x, y, width, height)
        screen_geometry = QApplication.primaryScreen().geometry()
        x = (screen_geometry.width() - 1200) // 2  # Center horizontally
        y = (screen_geometry.height() - 800) // 2   # Center vertically
        self.setGeometry(x, y, 1200, 800)
        
        # Set minimum size to prevent window from becoming too small
        self.setMinimumSize(800, 600)
        
        # Initialize variables
        self.packet_count = 0
        self.packet_list = []
        self.capture_worker = None
        self.capture_thread = None
        self.selected_packet = None
        self.packet_stats = PacketStats()

        # Initialize statistics variables
        self.total_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.protocol_stats = defaultdict(int)
        self.top_sources = defaultdict(int)
        self.top_destinations = defaultdict(int)
        self.port_stats = defaultdict(int)

        # Add statistics update throttling
        self.last_stats_update = 0
        self.stats_update_interval = 2.0
        self.last_chart_update = 0
        self.chart_update_interval = 2.0

        # Define packet filters
        self.packet_filters = {
            "All Packets": lambda _: True,
            "TCP Only": lambda p: TCP in p,
            "UDP Only": lambda p: UDP in p,
            "ICMP Only": lambda p: ICMP in p,
            "HTTP Traffic": lambda p: TCP in p and (p[TCP].dport == 80 or p[TCP].sport == 80),
            "DNS Queries": lambda p: DNS in p,
            "Large Packets (>1000 bytes)": lambda p: len(p) > 1000
        }
        self.current_filter = "All Packets"

        # Add PCAP file path storage
        self.pcap_file_path = None

        self.closing = False
        # Add cleanup on close
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self.init_ui()
        self.update_interfaces()

        # Setup update timer for statistics
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_statistics)
        self.update_timer.start(1000)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Left panel for packet capture and details
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        left_layout.setContentsMargins(5, 5, 5, 5)

        # Control panel with improved styling
        control_panel = QGroupBox("Capture Controls")
        control_panel.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #3b3b3b;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        control_layout = QHBoxLayout(control_panel)
        control_layout.setSpacing(10)

        # Interface selection with improved styling
        self.interface_combo = QComboBox()
        self.interface_combo.setStyleSheet("""
            QComboBox {
                background-color: #3b3b3b;
                color: white;
                border: 1px solid #4b4b4b;
                border-radius: 3px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
            }
        """)

        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_application)

        # Filter selection
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(self.packet_filters.keys())
        self.filter_combo.currentTextChanged.connect(self.change_filter)

        # Start/Stop buttons
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)

        # Set green color for all buttons
        button_style = """
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """
        self.start_btn.setStyleSheet(button_style)
        self.stop_btn.setStyleSheet(button_style)
        self.refresh_btn.setStyleSheet(button_style)

        # Add load data button
        self.load_data_btn = QPushButton("Load Saved Data")
        self.load_data_btn.clicked.connect(self.load_saved_data)
        self.load_data_btn.setStyleSheet(button_style)

        # Add widgets to control layout
        control_layout.addWidget(QLabel("Interface:"))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_combo)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.load_data_btn)
        control_layout.addStretch()

        left_layout.addWidget(control_panel)

        # Packet list table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.packet_table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: white;
                gridline-color: #3b3b3b;
                border: 1px solid #3b3b3b;
                border-radius: 3px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QHeaderView::section {
                background-color: #3b3b3b;
                color: white;
                padding: 5px;
                border: none;
            }
        """)
        self.packet_table.itemSelectionChanged.connect(self.on_packet_selected)
        left_layout.addWidget(self.packet_table)

        # Packet details
        details_group = QGroupBox("Packet Details")
        details_group.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #3b3b3b;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        details_layout = QVBoxLayout(details_group)

        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setStyleSheet("""
            QTextEdit {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #3b3b3b;
                border-radius: 3px;
                padding: 5px;
            }
        """)
        details_layout.addWidget(self.packet_details)

        left_layout.addWidget(details_group)
        main_layout.addWidget(left_panel)

        # Right panel for statistics
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setSpacing(10)
        right_layout.setContentsMargins(5, 5, 5, 5)

        # Statistics group
        stats_group = QGroupBox("Statistics")
        stats_group.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #3b3b3b;
                border-radius: 5px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        stats_layout = QVBoxLayout(stats_group)

        # Create figure for protocol distribution
        self.protocol_fig = Figure(figsize=(6, 4))
        self.protocol_canvas = FigureCanvas(self.protocol_fig)
        stats_layout.addWidget(self.protocol_canvas)

        # Create figure for traffic over time
        self.traffic_fig = Figure(figsize=(6, 4))
        self.traffic_canvas = FigureCanvas(self.traffic_fig)
        stats_layout.addWidget(self.traffic_canvas)

        right_layout.addWidget(stats_group)
        main_layout.addWidget(right_panel)

    def update_interfaces(self):
        """Update the list of available network interfaces"""
        try:
            # Get all interfaces
            interfaces = []
            for iface in scapy.get_working_ifaces():
                # Add interface name and description if available
                if hasattr(iface, 'description') and iface.description:
                    interfaces.append(f"{iface.name} ({iface.description})")
                else:
                    interfaces.append(iface.name)

            self.interface_combo.clear()
            self.interface_combo.addItems(interfaces)

            if not interfaces:
                QMessageBox.warning(self, "Warning", "No network interfaces found. Make sure you have administrator privileges.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get network interfaces: {str(e)}")

    def start_capture(self):
        """Start packet capture"""
        try:
            interface = self.interface_combo.currentText()
            if not interface:
                QMessageBox.warning(self, "Error", "Please select a network interface")
                return

            # Extract interface name from the combo box text (remove description if present)
            if "(" in interface:
                interface = interface.split("(")[0].strip()

            self.capture_worker = PacketCaptureWorker(interface)
            self.capture_worker.packet_captured.connect(self.process_packet)
            self.capture_worker.error_occurred.connect(self.handle_error)

            self.capture_thread = threading.Thread(target=self.capture_worker.start_capture)
            self.capture_thread.daemon = True
            self.capture_thread.start()

            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.interface_combo.setEnabled(False)
            self.filter_combo.setEnabled(False)

            QMessageBox.information(self, "Success", "Packet capture started")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {str(e)}")

    def stop_capture(self):
        """Stop packet capture"""
        try:
            if self.capture_worker:
                self.capture_worker.stop_capture()
                self.capture_thread.join(timeout=1.0)

            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.interface_combo.setEnabled(True)
            self.filter_combo.setEnabled(True)

            QMessageBox.information(self, "Success", "Packet capture stopped")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop capture: {str(e)}")

    def process_packet(self, packet):
        """Process a captured packet"""
        try:
            if self.packet_filters[self.current_filter](packet):
                self.packet_count += 1
                self.packet_stats.update(packet)
                self.packet_list.append(packet)

                # Add packet to table
                row = self.packet_table.rowCount()
                self.packet_table.insertRow(row)

                # Format time
                time_str = time.strftime("%H:%M:%S")

                # Get source and destination
                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                else:
                    src = "Unknown"
                    dst = "Unknown"

                # Get protocol
                if TCP in packet:
                    protocol = f"TCP ({packet[TCP].sport} -> {packet[TCP].dport})"
                elif UDP in packet:
                    protocol = f"UDP ({packet[UDP].sport} -> {packet[UDP].dport})"
                elif ICMP in packet:
                    protocol = "ICMP"
                else:
                    protocol = "Other"

                # Add items to table
                self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
                self.packet_table.setItem(row, 1, QTableWidgetItem(time_str))
                self.packet_table.setItem(row, 2, QTableWidgetItem(src))
                self.packet_table.setItem(row, 3, QTableWidgetItem(dst))
                self.packet_table.setItem(row, 4, QTableWidgetItem(protocol))

                # Scroll to bottom
                self.packet_table.scrollToBottom()
        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def on_packet_selected(self):
        """Handle packet selection in the table"""
        try:
            selected_items = self.packet_table.selectedItems()
            if not selected_items:
                return

            row = selected_items[0].row()
            packet = self.packet_list[row] if row < len(self.packet_list) else None

            if packet:
                self.selected_packet = packet
                self.update_packet_details(packet)
        except Exception as e:
            print(f"Error handling packet selection: {str(e)}")

    def update_packet_details(self, packet):
        """Display detailed packet information"""
        try:
            if not packet:
                return

            details = []
            details.append("<pre>")  # Using pre-formatted text for better layout

            # Timestamp and basic info
            details.append("═══════════════ PACKET SUMMARY ═══════════════")
            details.append(f"Capture Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            details.append(f"Total Length: {len(packet)} bytes")
            details.append("")

            # Layer 2 (Ethernet) details
            if Ether in packet:
                details.append("═══════════════ ETHERNET LAYER ═══════════════")
                eth = packet[Ether]
                details.append(f"Source MAC:      {eth.src}")
                details.append(f"Destination MAC: {eth.dst}")
                details.append(f"Ethernet Type:   0x{eth.type:04x}")
                details.append("")

            # Layer 3 (IP) details
            if IP in packet:
                details.append("═══════════════ IP LAYER ═══════════════")
                ip = packet[IP]
                details.append(f"Source IP:       {ip.src}")
                details.append(f"Destination IP:  {ip.dst}")
                details.append(f"Version:         IPv{ip.version}")
                details.append(f"TTL:            {ip.ttl}")
                details.append(f"Protocol:        {ip.proto} ({self.get_protocol_name(ip.proto)})")
                details.append(f"Length:         {ip.len} bytes")
                details.append(f"ID:             0x{ip.id:04x}")

                # IP Flags
                flags = []
                if ip.flags.DF: flags.append("Don't Fragment")
                if ip.flags.MF: flags.append("More Fragments")
                details.append(f"Flags:          {', '.join(flags) if flags else 'None'}")
                details.append("")

            # Layer 4 (TCP/UDP) details
            if TCP in packet:
                details.append("═══════════════ TCP LAYER ═══════════════")
                tcp = packet[TCP]
                details.append(f"Source Port:     {tcp.sport}")
                details.append(f"Destination Port: {tcp.dport}")
                details.append(f"Sequence Number: {tcp.seq}")
                details.append(f"ACK Number:      {tcp.ack}")
                details.append(f"Window Size:     {tcp.window}")

                # TCP Flags
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                if tcp.flags.P: flags.append("PSH")
                if tcp.flags.U: flags.append("URG")
                details.append(f"Flags:           {', '.join(flags)}")
                details.append("")

            elif UDP in packet:
                details.append("═══════════════ UDP LAYER ═══════════════")
                udp = packet[UDP]
                details.append(f"Source Port:     {udp.sport}")
                details.append(f"Destination Port: {udp.dport}")
                details.append(f"Length:          {udp.len} bytes")
                details.append("")

            elif ICMP in packet:
                details.append("═══════════════ ICMP LAYER ═══════════════")
                icmp = packet[ICMP]
                details.append(f"Type:            {icmp.type} ({self.get_icmp_type(icmp.type)})")
                details.append(f"Code:            {icmp.code}")
                details.append("")

            # Application Layer Details
            if HTTP in packet:
                details.append("═══════════════ HTTP LAYER ═══════════════")
                http = packet[HTTP]
                if hasattr(http, 'Method'):
                    details.append(f"Method:          {http.Method}")
                if hasattr(http, 'Path'):
                    details.append(f"Path:            {http.Path}")
                if hasattr(http, 'Status-Line'):
                    details.append(f"Status:          {http['Status-Line']}")
                details.append("")

            if DNS in packet:
                details.append("═══════════════ DNS LAYER ═══════════════")
                dns = packet[DNS]
                details.append(f"Transaction ID:  0x{dns.id:04x}")
                if dns.qr == 0:
                    details.append("Type:            Query")
                    if dns.qd:
                        details.append(f"Query Name:      {dns.qd.qname.decode()}")
                else:
                    details.append("Type:            Response")
                    details.append(f"Answer Count:    {dns.ancount}")
                details.append("")

            # Payload Analysis
            if Raw in packet:
                details.append("═══════════════ PAYLOAD ═══════════════")
                raw_data = bytes(packet[Raw])

                # Hex dump (first 128 bytes)
                details.append("Hex Dump (first 128 bytes):")
                hex_dump = ' '.join([f'{b:02x}' for b in raw_data[:128]])
                details.append(self.format_hex_dump(hex_dump))

                # ASCII representation
                details.append("\nASCII Representation:")
                ascii_data = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_data[:128]])
                details.append(ascii_data)

            details.append("</pre>")
            self.packet_details.setHtml('\n'.join(details))

        except Exception as e:
            self.packet_details.setPlainText(f"Error displaying packet details: {str(e)}")

    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            89: "OSPF"
        }
        return protocols.get(protocol_num, str(protocol_num))

    def get_icmp_type(self, icmp_type):
        """Convert ICMP type to description"""
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded"
        }
        return icmp_types.get(icmp_type, str(icmp_type))

    def format_hex_dump(self, hex_string):
        """Format hex dump in 16-byte lines"""
        bytes_per_line = 16
        hex_bytes = hex_string.split()
        lines = []

        for i in range(0, len(hex_bytes), bytes_per_line):
            line_bytes = hex_bytes[i:i + bytes_per_line]
            offset = f"{i:04x}"
            hex_part = ' '.join(line_bytes).ljust(bytes_per_line * 3)
            lines.append(f"{offset}  {hex_part}")

        return '\n'.join(lines)

    def change_filter(self, filter_name):
        """Change the current packet filter"""
        self.current_filter = filter_name
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.packet_stats = PacketStats()

    def update_statistics(self):
        """Update the statistics displays"""
        if self.closing:
            return

        try:
            current_time = time.time()

            # Update protocol distribution chart
            if current_time - self.last_chart_update >= self.chart_update_interval:
                self.update_protocol_chart()
                self.last_chart_update = current_time

            # Update traffic chart
            if current_time - self.last_chart_update >= self.chart_update_interval:
                self.update_traffic_chart()
                self.last_chart_update = current_time

            # Update statistics from packet_stats
            self.total_packets = self.packet_stats.total_packets
            self.tcp_packets = self.packet_stats.tcp_packets
            self.udp_packets = self.packet_stats.udp_packets
            self.icmp_packets = self.packet_stats.icmp_packets
            self.protocol_stats = self.packet_stats.protocol_stats
            self.port_stats = self.packet_stats.port_stats

            # Update top sources and destinations
            self.top_sources = self.packet_stats.ip_stats
            self.top_destinations = self.packet_stats.ip_stats

            # Emit data for report
            self.dataReady.emit({
                'total_packets': self.total_packets,
                'tcp_packets': self.tcp_packets,
                'udp_packets': self.udp_packets,
                'icmp_packets': self.icmp_packets,
                'protocol_stats': self.protocol_stats,
                'top_sources': self.top_sources,
                'top_destinations': self.top_destinations,
                'port_stats': self.port_stats
            })
        except Exception as e:
            print(f"Error updating statistics: {str(e)}")

    def update_protocol_chart(self):
        """Update the protocol distribution chart"""
        try:
            self.protocol_fig.clear()
            ax = self.protocol_fig.add_subplot(111)

            percentages = self.packet_stats.get_percentages()
            protocols = list(percentages.keys())
            values = list(percentages.values())

            # Only create pie chart if there's data
            if sum(values) > 0:
                ax.pie(values, labels=protocols, autopct='%1.1f%%')
                ax.set_title('Protocol Distribution')
            else:
                ax.text(0.5, 0.5, 'No packets captured yet',
                       horizontalalignment='center',
                       verticalalignment='center')
                ax.set_title('Protocol Distribution')
                ax.set_xticks([])
                ax.set_yticks([])

            self.protocol_canvas.draw()
        except Exception as e:
            print(f"Error updating protocol chart: {str(e)}")

    def update_traffic_chart(self):
        """Update the traffic over time chart"""
        try:
            self.traffic_fig.clear()
            ax = self.traffic_fig.add_subplot(111)

            # Create time series data
            if self.packet_count > 0:
                times = range(self.packet_count)
                values = [1] * self.packet_count  # Simple packet count

                ax.plot(times, values, 'b-')
                ax.set_title('Traffic Over Time')
                ax.set_xlabel('Packet Number')
                ax.set_ylabel('Packets')
            else:
                ax.text(0.5, 0.5, 'No packets captured yet',
                       horizontalalignment='center',
                       verticalalignment='center')
                ax.set_title('Traffic Over Time')
                ax.set_xticks([])
                ax.set_yticks([])

            self.traffic_canvas.draw()
        except Exception as e:
            print(f"Error updating traffic chart: {str(e)}")

    def handle_error(self, error_message):
        """Handle errors from the packet capture worker"""
        QMessageBox.critical(self, "Error", f"Packet capture error: {error_message}")

    def refresh_application(self):
        """Refresh the application state"""
        self.update_interfaces()
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.packet_list = []
        self.packet_stats = PacketStats()
        self.packet_details.clear()
        self.update_protocol_chart()
        self.update_traffic_chart()

    def load_saved_data(self):
        """Load and display data from real_time_packet.json"""
        try:
            json_file = os.path.join('data_temp', 'real_time_packet.json')
            if not os.path.exists(json_file):
                QMessageBox.warning(self, "Warning", "No saved data file found.")
                return

            with open(json_file, 'r') as f:
                data = json.load(f)

            # Clear existing data
            self.packet_table.setRowCount(0)
            self.packet_list = []
            self.packet_count = 0

            # Load packets
            for packet_data in data['packets']:
                self.packet_count += 1
                row = self.packet_table.rowCount()
                self.packet_table.insertRow(row)

                # Add items to table
                self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
                self.packet_table.setItem(row, 1, QTableWidgetItem(packet_data['timestamp']))
                self.packet_table.setItem(row, 2, QTableWidgetItem(packet_data['source_ip']))
                self.packet_table.setItem(row, 3, QTableWidgetItem(packet_data['dest_ip']))
                self.packet_table.setItem(row, 4, QTableWidgetItem(packet_data['protocol']))

            # Update statistics
            stats = data['statistics']
            self.packet_stats.total_packets = stats['total_packets']
            self.packet_stats.tcp_packets = stats['tcp_packets']
            self.packet_stats.udp_packets = stats['udp_packets']
            self.packet_stats.icmp_packets = stats['icmp_packets']
            self.packet_stats.other_packets = stats['other_packets']
            self.packet_stats.total_bytes = stats['total_bytes']
            self.packet_stats.tcp_bytes = stats['tcp_bytes']
            self.packet_stats.udp_bytes = stats['udp_bytes']
            self.packet_stats.icmp_bytes = stats['icmp_bytes']
            self.packet_stats.other_bytes = stats['other_bytes']
            self.packet_stats.protocol_stats = defaultdict(int, stats['protocol_stats'])
            self.packet_stats.port_stats = defaultdict(int, stats['port_stats'])
            self.packet_stats.ip_stats = defaultdict(int, stats['ip_stats'])

            # Update charts
            self.update_protocol_chart()
            self.update_traffic_chart()

            QMessageBox.information(self, "Success", "Data loaded successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load data: {str(e)}")

    # Removed generate_report method as we're now using a centralized report approach

    def closeEvent(self, event):
        """Handle window closing"""
        try:
            # Save final data before closing
            if hasattr(self, 'packet_stats'):
                self.packet_stats.save_to_json()

            # Disconnect all signals
            try:
                self.dataReady.disconnect()
            except:
                pass

            event.accept()
        except Exception as e:
            print(f"Error during PacketAnalyzer cleanup: {e}")
            event.accept()

    def resizeEvent(self, event):
        """Handle window resize events"""
        super().resizeEvent(event)
        
        # Update table columns when window is resized
        if hasattr(self, 'packet_table'):
            header = self.packet_table.horizontalHeader()
            for i in range(5):  # Adjust all 5 columns
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        
        # Update charts if they exist
        if hasattr(self, 'protocol_canvas'):
            self.protocol_canvas.draw()
        if hasattr(self, 'traffic_canvas'):
            self.traffic_canvas.draw()

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        window = PacketAnalyzer()
        window.show()
        sys.exit(app.exec())
    except KeyboardInterrupt:
        print("\nApplication terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)










