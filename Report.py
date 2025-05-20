import sys
import socket
import psutil
import datetime
import json
import subprocess
import platform
import netifaces
import speedtest
import os
from functools import lru_cache
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QPushButton, QLabel, QTextEdit, QFileDialog,
                            QMessageBox, QProgressDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

class NetworkInfoWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def run(self):
        try:
            print("NetworkInfoWorker started")
            network_info = {}

            # Get system information (cached)
            print("Getting system info...")
            network_info['system'] = self._get_system_info()
            self.progress.emit(20)

            # Get IP addresses and interfaces (cached)
            print("Getting IP addresses...")
            network_info['ip_addresses'] = self._get_ip_addresses()
            self.progress.emit(40)

            # Get network interfaces (cached)
            print("Getting network interfaces...")
            network_info['interfaces'] = self._get_network_interfaces()
            self.progress.emit(60)

            # Get network connections (cached)
            print("Getting network connections...")
            network_info['connections'] = self._get_network_connections()
            self.progress.emit(80)

            # Get network I/O statistics (cached)
            print("Getting I/O stats...")
            network_info['io_stats'] = self._get_io_stats()
            self.progress.emit(90)

            # Get default gateway (cached)
            print("Getting default gateway...")
            network_info['default_gateway'] = self._get_default_gateway()

            # Get DNS servers (cached)
            print("Getting DNS servers...")
            network_info['dns_servers'] = self._get_dns_servers()

            # Get network speed test (async)
            try:
                print("Running speed test...")
                network_info['speed_test'] = self._get_speed_test()
            except Exception as e:
                print(f"Speed test error: {e}")
                network_info['speed_test'] = "Not available"

            self.progress.emit(100)
            print("NetworkInfoWorker completed successfully")
            self.finished.emit(network_info)

        except Exception as e:
            print(f"NetworkInfoWorker error: {str(e)}")
            self.error.emit(str(e))

    @lru_cache(maxsize=1)
    def _get_system_info(self):
        return {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname())
        }

    @lru_cache(maxsize=1)
    def _get_ip_addresses(self):
        ip_addresses = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_addresses.append({
                        'interface': interface,
                        'ip': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
        return ip_addresses

    @lru_cache(maxsize=1)
    def _get_network_interfaces(self):
        interfaces = {}
        for interface, stats in psutil.net_if_stats().items():
            interfaces[interface] = {
                'speed': stats.speed,
                'mtu': stats.mtu,
                'isup': stats.isup,
                'duplex': stats.duplex,
                'flags': stats.flags
            }
        return interfaces

    @lru_cache(maxsize=1)
    def _get_network_connections(self):
        connections = []
        for conn in psutil.net_connections():
            connections.append({
                'fd': conn.fd,
                'family': conn.family,
                'type': conn.type,
                'local_addr': conn.laddr,
                'remote_addr': conn.raddr,
                'status': conn.status,
                'pid': conn.pid
            })
        return connections

    @lru_cache(maxsize=1)
    def _get_io_stats(self):
        return psutil.net_io_counters()

    @lru_cache(maxsize=1)
    def _get_default_gateway(self):
        return netifaces.gateways()['default'][netifaces.AF_INET][0]

    @lru_cache(maxsize=1)
    def _get_dns_servers(self):
        try:
            return subprocess.check_output(['ipconfig', '/all']).decode('utf-8')
        except:
            return "Unable to get DNS servers"

    def _get_speed_test(self):
        try:
            print("Initializing speedtest...")
            st = speedtest.Speedtest()
            print("Getting best server...")
            st.get_best_server()
            print("Testing download speed...")
            download = st.download() / 1_000_000
            print(f"Download speed: {download:.2f} Mbps")
            print("Testing upload speed...")
            upload = st.upload() / 1_000_000
            print(f"Upload speed: {upload:.2f} Mbps")
            print("Getting ping...")
            ping = st.results.ping
            print(f"Ping: {ping:.2f} ms")

            return {
                'download_speed': download,
                'upload_speed': upload,
                'ping': ping
            }
        except Exception as e:
            print(f"Speed test failed with error: {str(e)}")
            # Return a dictionary with default values to avoid type errors
            return {
                'download_speed': 0.0,
                'upload_speed': 0.0,
                'ping': 0.0
            }

class UserHistory:
    def __init__(self):
        # Get the directory where the script is located
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.history_file = os.path.join(self.script_dir, 'user_history.json')
        self.history = self.load_history()
        print(f"UserHistory initialized with {len(self.history)} entries")

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        print(f"Loaded {len(data)} history entries from {self.history_file}")
                        return data
                    else:
                        print(f"Invalid history data format in {self.history_file}")
                        return []
            print(f"History file {self.history_file} does not exist")
            return []
        except Exception as e:
            print(f"Error loading history: {e}")
            return []

    def save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=4)
            print(f"Saved {len(self.history)} history entries to {self.history_file}")
        except Exception as e:
            print(f"Error saving history: {e}")

    def add_action(self, action_type, details=None):
        try:
            entry = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'action_type': action_type,
                'details': details or {}
            }
            if not isinstance(self.history, list):
                print(f"History is not a list, resetting: {type(self.history)}")
                self.history = []
            self.history.append(entry)
            self.save_history()
            print(f"Added action: {action_type}")
        except Exception as e:
            print(f"Error adding action: {e}")

    def clear_history(self):
        self.history = []
        self.save_history()
        print("History cleared")

    def get_history_file_path(self):
        return self.history_file

    def get_actions(self):
        try:
            if not isinstance(self.history, list):
                print(f"History is not a list: {type(self.history)}")
                return []
            return self.history
        except Exception as e:
            print(f"Error getting actions: {e}")
            return []

class SaveInterface(QMainWindow):
    def __init__(self, parent=None):
        try:
            super().__init__(parent)
            print("SaveInterface initialization started")
            self.network_info = None
            self.worker = None
            self.history = UserHistory()

            # Initialize data containers for different modules
            self.packet_analysis_data = {}
            self.wifi_scanner_data = {}
            self.network_device_scan_data = {}
            self.network_troubleshoot_data = {}
            self.monitoring_data = {}

            # Initialize data directory
            self.data_dir = 'data_temp'
            if not os.path.exists(self.data_dir):
                os.makedirs(self.data_dir)

            print("Initializing UI...")
            self.initUI()
            print("Setting up connections...")
            self.setupConnections()
            print("Generating network report...")
            self.generateNetworkReport()

            # Set up timer for periodic updates
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self.generateNetworkReport)
            self.update_timer.start(30000)  # Update every 30 seconds

            # Track application start
            self.history.add_action('application_start', {
                'window_title': self.windowTitle(),
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            print("SaveInterface initialization completed successfully")
        except Exception as e:
            print(f"Error initializing SaveInterface: {str(e)}")
            raise Exception(f"Failed to initialize SaveInterface: {str(e)}")

    def closeEvent(self, event):
        # Track application close
        self.history.add_action('application_close', {
            'window_title': self.windowTitle(),
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

        # Ask user if they want to generate a final report before closing
        reply = QMessageBox.question(
            self,
            "Generate Final Report",
            "Would you like to generate a comprehensive PDF report with all test details before closing?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.saveReportAsPDF(is_final_report=True)

        # Ask user if they want to clean temporary files
        clean_reply = QMessageBox.question(
            self,
            "Clean Temporary Files",
            "Do you want to clean temporary data files before closing?\n\n"
            "This will remove all saved data from your analysis sessions.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if clean_reply == QMessageBox.StandardButton.Yes:
            self.clean_temp_files()

        super().closeEvent(event)

    def initUI(self):
        # Set window properties
        self.setWindowTitle('Network Administrator Report Generator')
        self.setGeometry(100, 100, 1000, 800)

        # Central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Top section with buttons
        top_layout = QHBoxLayout()

        # Save PDF button
        self.save_pdf_btn = QPushButton('Save as PDF')
        self.save_pdf_btn.setStyleSheet('''
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 16px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        ''')
        self.save_pdf_btn.setFixedSize(120, 40)
        top_layout.addWidget(self.save_pdf_btn)

        # Comprehensive Report button
        self.comprehensive_report_btn = QPushButton('Comprehensive Report')
        self.comprehensive_report_btn.setStyleSheet('''
            QPushButton {
                background-color: #FF9800;
                color: white;
                padding: 10px;
                font-size: 16px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        ''')
        self.comprehensive_report_btn.setFixedSize(180, 40)
        self.comprehensive_report_btn.setToolTip('Generate a comprehensive report with all test details')
        top_layout.addWidget(self.comprehensive_report_btn)

        # Refresh button
        self.refresh_btn = QPushButton('Refresh')
        self.refresh_btn.setStyleSheet('''
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 10px;
                font-size: 16px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        ''')
        self.refresh_btn.setFixedSize(120, 40)
        top_layout.addWidget(self.refresh_btn)

        # Add top layout to main layout
        main_layout.addLayout(top_layout)

        # Text areas layout
        text_areas_layout = QHBoxLayout()

        # Left text area (Network Details)
        left_section = QWidget()
        left_layout = QVBoxLayout()
        list_report_label = QLabel('Network Details')
        list_report_label.setStyleSheet('font-size: 14px; font-weight: bold;')
        self.left_text_area = QTextEdit()
        self.left_text_area.setStyleSheet('''
            QTextEdit {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
            }
        ''')
        left_layout.addWidget(list_report_label)
        left_layout.addWidget(self.left_text_area)
        left_section.setLayout(left_layout)

        # Right text area (Report Summary)
        right_section = QWidget()
        right_layout = QVBoxLayout()
        report_view_label = QLabel('Report Summary')
        report_view_label.setStyleSheet('font-size: 14px; font-weight: bold;')
        self.right_text_area = QTextEdit()
        self.right_text_area.setStyleSheet('''
            QTextEdit {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
            }
        ''')
        right_layout.addWidget(report_view_label)
        right_layout.addWidget(self.right_text_area)
        right_section.setLayout(right_layout)

        # Add both sections to the text areas layout
        text_areas_layout.addWidget(left_section)
        text_areas_layout.addWidget(right_section)

        # Add the text areas layout to main layout
        main_layout.addLayout(text_areas_layout)

        # Set window style
        self.setStyleSheet('''
            QMainWindow {
                background-color: white;
            }
            QLabel {
                color: #333;
                margin-bottom: 5px;
            }
            QWidget {
                font-family: Arial;
            }
        ''')

    def setupConnections(self):
        self.save_pdf_btn.clicked.connect(lambda: self.saveReportAsPDF(is_final_report=False))
        self.comprehensive_report_btn.clicked.connect(lambda: self.saveReportAsPDF(is_final_report=True))
        self.refresh_btn.clicked.connect(self.generateNetworkReport)

    def generateSilentReport(self, external_progress_callback=None):
        """Generate a report silently using only data from temp folder without any user interaction"""
        try:
            # Update progress if callback provided
            if external_progress_callback:
                external_progress_callback(10)

            # Initialize basic network info if not already available
            if not self.network_info:
                # Create minimal network info structure to avoid errors
                self.network_info = {
                    'system': {
                        'platform': platform.system(),
                        'platform_release': platform.release(),
                        'platform_version': platform.version(),
                        'architecture': platform.machine(),
                        'processor': platform.processor(),
                        'hostname': socket.gethostname(),
                        'ip_address': socket.gethostbyname(socket.gethostname())
                    },
                    'default_gateway': 'N/A',
                    'interfaces': {},
                    'ip_addresses': [],
                    'connections': [],
                    'io_stats': psutil.net_io_counters(),
                    'speed_test': {'download_speed': 0, 'upload_speed': 0, 'ping': 0}
                }

                # Try to get some basic interface info
                try:
                    for interface in netifaces.interfaces():
                        self.network_info['interfaces'][interface] = {
                            'speed': 0,
                            'mtu': 1500,
                            'isup': True,
                            'duplex': 'unknown',
                            'flags': ''
                        }

                        # Try to get IP addresses
                        try:
                            addrs = netifaces.ifaddresses(interface)
                            if netifaces.AF_INET in addrs:
                                for addr in addrs[netifaces.AF_INET]:
                                    self.network_info['ip_addresses'].append({
                                        'interface': interface,
                                        'ip': addr.get('addr', 'N/A'),
                                        'netmask': addr.get('netmask', 'N/A'),
                                        'broadcast': addr.get('broadcast', 'N/A')
                                    })
                        except Exception as e:
                            print(f"Error getting addresses for interface {interface}: {e}")
                except Exception as e:
                    print(f"Error getting interfaces: {e}")

            # Update progress if callback provided
            if external_progress_callback:
                external_progress_callback(40)

            # Load data from temp folder
            self.load_module_data()

            # Update progress if callback provided
            if external_progress_callback:
                external_progress_callback(70)

            # Generate the PDF without asking the user
            self.generateSilentPDF()

            # Update progress if callback provided
            if external_progress_callback:
                external_progress_callback(100)

            return True
        except Exception as e:
            print(f"Error generating silent report: {e}")
            return False

    def generateSilentPDF(self):
        """Generate a PDF report without any user interaction and save to root folder"""
        try:
            # Set filename in project root folder
            script_dir = os.path.dirname(os.path.abspath(__file__))
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            file_name = os.path.join(script_dir, f"Network_Report_{timestamp}.pdf")

            # Create PDF document
            doc = SimpleDocTemplate(file_name, pagesize=letter)
            styles = getSampleStyleSheet()
            title_style = styles['Heading1']
            heading_style = styles['Heading2']
            normal_style = styles['Normal']

            # Create content
            content = []

            # Add title
            content.append(Paragraph("Network Analysis Report", title_style))
            content.append(Spacer(1, 12))

            # Add timestamp
            content.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
            content.append(Spacer(1, 12))

            # Add system information
            content.append(Paragraph("System Information", heading_style))
            content.append(Spacer(1, 6))

            system_info = self.network_info['system']
            system_data = [
                ["Platform", f"{system_info['platform']} {system_info['platform_release']}"],
                ["Version", system_info['platform_version']],
                ["Architecture", system_info['architecture']],
                ["Processor", system_info['processor']],
                ["Hostname", system_info['hostname']],
                ["IP Address", system_info['ip_address']]
            ]

            system_table = Table(system_data, colWidths=[2*inch, 4*inch])
            system_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            content.append(system_table)
            content.append(Spacer(1, 12))

            # Add hardware information
            content.append(Paragraph("Hardware Information", heading_style))
            content.append(Spacer(1, 6))

            # Get CPU information
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq() or type('obj', (object,), {'current': 0})
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            hardware_data = [
                ["Component", "Details"],
                ["CPU Usage", f"{cpu_percent}%"],
                ["CPU Cores", str(cpu_count)],
                ["CPU Frequency", f"{cpu_freq.current:.2f} MHz"],
                ["Memory Total", f"{memory.total / (1024**3):.2f} GB"],
                ["Memory Used", f"{memory.used / (1024**3):.2f} GB"],
                ["Memory Free", f"{memory.free / (1024**3):.2f} GB"],
                ["Disk Total", f"{disk.total / (1024**3):.2f} GB"],
                ["Disk Used", f"{disk.used / (1024**3):.2f} GB"],
                ["Disk Free", f"{disk.free / (1024**3):.2f} GB"]
            ]

            hardware_table = Table(hardware_data, colWidths=[2*inch, 2*inch])
            hardware_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            content.append(hardware_table)
            content.append(Spacer(1, 12))

            # Add packet analysis data if available
            if hasattr(self, 'packet_analysis_data') and self.packet_analysis_data:
                content.append(Paragraph("Network Packet Analysis", heading_style))
                content.append(Spacer(1, 6))

                # Extract packet statistics
                packet_stats = []
                packet_stats.append(["Metric", "Value"])

                # Handle different data structures
                if isinstance(self.packet_analysis_data, dict):
                    # Try to get packet stats from top level or nested 'statistics' key
                    stats = self.packet_analysis_data
                    if 'statistics' in self.packet_analysis_data and isinstance(self.packet_analysis_data['statistics'], dict):
                        stats = self.packet_analysis_data['statistics']

                    if 'total_packets' in stats:
                        packet_stats.append(["Total Packets", str(stats.get('total_packets', 0))])
                    if 'tcp_packets' in stats:
                        packet_stats.append(["TCP Packets", str(stats.get('tcp_packets', 0))])
                    if 'udp_packets' in stats:
                        packet_stats.append(["UDP Packets", str(stats.get('udp_packets', 0))])
                    if 'icmp_packets' in stats:
                        packet_stats.append(["ICMP Packets", str(stats.get('icmp_packets', 0))])
                    if 'total_bytes' in stats:
                        packet_stats.append(["Total Bytes", f"{stats.get('total_bytes', 0) / (1024*1024):.2f} MB"])
                elif isinstance(self.packet_analysis_data, list):
                    # If it's a list, just show the count
                    packet_stats.append(["Total Packets", str(len(self.packet_analysis_data))])

                # Create packet statistics table
                if len(packet_stats) > 1:  # Only create table if we have data
                    packet_table = Table(packet_stats, colWidths=[2*inch, 2*inch])
                    packet_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    content.append(packet_table)
                else:
                    content.append(Paragraph("No detailed packet statistics available", normal_style))

                content.append(Spacer(1, 12))

            # Add WiFi scanner data if available
            if hasattr(self, 'wifi_scanner_data') and self.wifi_scanner_data:
                content.append(Paragraph("WiFi Networks", heading_style))
                content.append(Spacer(1, 6))

                # Extract WiFi networks
                wifi_data = []
                wifi_data.append(["SSID", "Signal Strength", "Security", "Channel"])

                # Handle different data structures
                networks = []
                if isinstance(self.wifi_scanner_data, dict) and 'networks' in self.wifi_scanner_data:
                    networks = self.wifi_scanner_data.get('networks', [])
                elif isinstance(self.wifi_scanner_data, list):
                    networks = self.wifi_scanner_data

                if isinstance(networks, list) and networks:
                    for network in networks[:10]:  # Limit to 10 networks to keep report manageable
                        if isinstance(network, dict):
                            ssid = network.get('ssid', network.get('SSID', 'Unknown'))
                            signal = network.get('signal_strength', network.get('signal', 'Unknown'))
                            security = network.get('security', network.get('Security', 'Unknown'))
                            channel = network.get('channel', network.get('Channel', 'Unknown'))
                            wifi_data.append([ssid, signal, security, channel])

                # Create WiFi networks table
                if len(wifi_data) > 1:  # Only create table if we have data
                    wifi_table = Table(wifi_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
                    wifi_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    content.append(wifi_table)
                else:
                    content.append(Paragraph("No WiFi networks data available", normal_style))

                content.append(Spacer(1, 12))

            # Add network device scan data if available
            if hasattr(self, 'network_device_scan_data') and self.network_device_scan_data:
                content.append(Paragraph("Network Devices", heading_style))
                content.append(Spacer(1, 6))

                # Extract device data
                device_data = []
                device_data.append(["IP Address", "Hostname", "MAC Address", "Status"])

                # Handle different data structures
                devices = []
                if isinstance(self.network_device_scan_data, dict):
                    if 'devices' in self.network_device_scan_data:
                        devices = self.network_device_scan_data.get('devices', [])
                    elif 'results' in self.network_device_scan_data:
                        results = self.network_device_scan_data.get('results', {})
                        if isinstance(results, dict):
                            if 'online_devices' in results:
                                devices = results.get('online_devices', [])
                            elif 'devices' in results:
                                devices = results.get('devices', [])
                elif isinstance(self.network_device_scan_data, list):
                    devices = self.network_device_scan_data

                if isinstance(devices, list) and devices:
                    for device in devices[:15]:  # Limit to 15 devices
                        if isinstance(device, dict):
                            ip = device.get('ip', device.get('IP', 'Unknown'))
                            hostname = device.get('hostname', device.get('Hostname', 'Unknown'))
                            mac = device.get('mac', device.get('MAC', 'Unknown'))
                            status = device.get('status', device.get('Status', 'Unknown'))
                            device_data.append([ip, hostname, mac, status])

                # Create devices table
                if len(device_data) > 1:  # Only create table if we have data
                    device_table = Table(device_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
                    device_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    content.append(device_table)
                else:
                    content.append(Paragraph("No network device data available", normal_style))

                content.append(Spacer(1, 12))

            # Add troubleshooting data if available
            if hasattr(self, 'network_troubleshoot_data') and self.network_troubleshoot_data:
                content.append(Paragraph("Troubleshooting Summary", heading_style))
                content.append(Spacer(1, 6))

                # Extract troubleshooting data
                trouble_data = []
                trouble_data.append(["Timestamp", "Action Type", "Details"])

                # Handle different data structures
                entries = []
                if isinstance(self.network_troubleshoot_data, list):
                    entries = self.network_troubleshoot_data
                elif isinstance(self.network_troubleshoot_data, dict) and 'history' in self.network_troubleshoot_data:
                    entries = self.network_troubleshoot_data['history']

                if isinstance(entries, list) and entries:
                    # Define a helper function to format troubleshooting details
                    def format_details(entry_dict):
                        action = entry_dict.get('action_type', entry_dict.get('type', 'Unknown'))
                        details_data = entry_dict.get('details', entry_dict.get('result', 'N/A'))

                        # Default formatted details
                        formatted_details = str(details_data)

                        # Format based on action type and details structure
                        if isinstance(details_data, dict):
                            if action == 'ip_resolved':
                                url = details_data.get('url', '')
                                ip = details_data.get('ip_address', '')
                                formatted_details = f"URL: {url} → IP: {ip}"
                            elif action == 'status_check_complete':
                                status_info = details_data.get('status_info', '')
                                formatted_details = str(status_info).replace('\n', ' ')
                            elif action == 'dns_records_complete':
                                formatted_details = "DNS records retrieved"
                            elif action == 'ssl_check_complete':
                                formatted_details = "SSL certificate verified"
                            elif action == 'dns_lookup_complete':
                                formatted_details = "DNS lookup completed"
                            elif action == 'ping_complete':
                                formatted_details = "Ping completed successfully"
                            elif action == 'traceroute_complete':
                                formatted_details = "Traceroute completed"
                            elif action == 'analysis_started' or action == 'analysis_complete':
                                url = details_data.get('url', '')
                                formatted_details = f"Target: {url}"
                            elif action == 'application_start' or action == 'application_close':
                                window_title = details_data.get('window_title', '')
                                formatted_details = f"{window_title}"
                            else:
                                # For other types, extract key info
                                key_info = [f"{k}: {v}" for k, v in details_data.items()
                                           if k != 'timestamp' and isinstance(v, (str, int, float))]
                                if key_info:
                                    formatted_details = ", ".join(key_info[:2])  # Limit to first 2 items

                        # Limit length for any string
                        if isinstance(formatted_details, str) and len(formatted_details) > 50:
                            formatted_details = formatted_details[:47] + "..."

                        return formatted_details

                    # Process the entries
                    for entry in entries[-10:]:  # Show last 10 entries
                        if isinstance(entry, dict):
                            timestamp = entry.get('timestamp', 'Unknown')
                            action = entry.get('action_type', entry.get('type', 'Unknown'))
                            formatted_details = format_details(entry)
                            trouble_data.append([timestamp, action, formatted_details])

                # Create troubleshooting table
                if len(trouble_data) > 1:  # Only create table if we have data
                    trouble_table = Table(trouble_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
                    trouble_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    content.append(trouble_table)
                else:
                    content.append(Paragraph("No troubleshooting data available", normal_style))

                content.append(Spacer(1, 12))

            # Build PDF
            doc.build(content)
            print(f"Silent report generated successfully: {file_name}")

            # Track successful PDF save
            self.history.add_action('silent_pdf_generated', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'file_name': file_name
            })

            return file_name
        except Exception as e:
            print(f"Error generating silent PDF: {e}")
            return None

    def generateNetworkReport(self, external_progress_callback=None):
        # Track report generation
        self.history.add_action('report_generation_start', {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

        # Create and start worker thread
        self.worker = NetworkInfoWorker()

        # Connect to external progress callback if provided, otherwise use internal handling
        if external_progress_callback:
            self.worker.progress.connect(external_progress_callback)

        self.worker.finished.connect(self.updateReport)
        self.worker.error.connect(self.handleError)
        self.worker.start()

    def updateReport(self, network_info):
        try:
            print("Updating report with network info...")
            self.network_info = network_info

            # Load data from other modules
            print("Loading module data...")
            self.load_module_data()

            print("Updating text areas...")
            self.updateTextAreas()

            # Track successful report generation
            self.history.add_action('report_generation_complete', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'network_info_summary': {
                    'interfaces_count': len(network_info['interfaces']),
                    'connections_count': len(network_info['connections']),
                    'ip_addresses_count': len(network_info['ip_addresses'])
                }
            })
            print("Report updated successfully")
        except Exception as e:
            print(f"Error updating report: {str(e)}")
            self.handleError(f"Failed to update report: {str(e)}")

    def load_module_data(self):
        """Load data from all available module JSON files"""
        try:
            # Make sure data directory exists
            if not os.path.exists(self.data_dir):
                os.makedirs(self.data_dir)

            # Dictionary of module data files to check
            data_files = {
                'packet_analysis_data': 'real_time_packet.json',
                'wifi_scanner_data': 'wifi_signals_details.json',
                'network_device_scan_data': 'network_device_and_vulnerability_scan.json',
                'monitoring_data': 'monitoring_dashboard.json',
                'network_troubleshoot_data': 'network_troubleshoot_history.json'
            }

            # Load data from each file if it exists
            for attr_name, filename in data_files.items():
                file_path = os.path.join(self.data_dir, filename)

                # Special case for troubleshoot history which might be in the main directory
                if attr_name == 'network_troubleshoot_data' and not os.path.exists(file_path):
                    alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
                    if os.path.exists(alt_path):
                        file_path = alt_path

                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            setattr(self, attr_name, data)
                            print(f"Loaded {attr_name} from {file_path}")

                            # Track successful data load
                            self.history.add_action(f'{attr_name}_loaded', {
                                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'file_path': file_path,
                                'data_size': os.path.getsize(file_path)
                            })
                    except Exception as e:
                        print(f"Error loading {attr_name} from {file_path}: {e}")
                else:
                    print(f"File not found: {file_path}")

        except Exception as e:
            print(f"Error loading module data: {e}")
            self.history.add_action('data_load_error', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error': str(e)
            })

    def gather_packet_analysis_data(self, data):
        """Receive data from packet analyzer module"""
        try:
            self.packet_analysis_data = data
            self.history.add_action('packet_data_received', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'data_size': len(str(data))
            })
        except Exception as e:
            print(f"Error gathering packet analysis data: {e}")

    def gather_wifi_scanner_data(self, data):
        """Receive data from WiFi scanner module"""
        try:
            self.wifi_scanner_data = data
            self.history.add_action('wifi_data_received', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'data_size': len(str(data))
            })
        except Exception as e:
            print(f"Error gathering WiFi scanner data: {e}")

    def gather_network_device_scan_data(self, data):
        """Receive data from network device scan module"""
        try:
            self.network_device_scan_data = data
            self.history.add_action('device_scan_data_received', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'data_size': len(str(data))
            })
        except Exception as e:
            print(f"Error gathering network device scan data: {e}")

    def gather_troubleshoot_data(self, data):
        """Receive data from network troubleshoot module"""
        try:
            self.network_troubleshoot_data = data
            self.history.add_action('troubleshoot_data_received', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'data_size': len(str(data))
            })
        except Exception as e:
            print(f"Error gathering network troubleshoot data: {e}")

    def gather_monitoring_data(self, data):
        """Receive data from network monitoring module"""
        try:
            self.monitoring_data = data
            self.history.add_action('monitoring_data_received', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'data_size': len(str(data))
            })
        except Exception as e:
            print(f"Error gathering monitoring data: {e}")

    def clean_temp_files(self):
        """Clean temporary data files"""
        try:
            # List of files to clean
            files_to_clean = [
                'real_time_packet.json',
                'wifi_signals_details.json',
                'network_device_and_vulnerability_scan.json',
                'monitoring_dashboard.json'
                # Note: We don't delete network_troubleshoot_history.json as it's a persistent history
            ]

            # Count of files deleted
            deleted_count = 0

            # Delete each file if it exists
            for filename in files_to_clean:
                file_path = os.path.join(self.data_dir, filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_count += 1
                    print(f"Deleted {file_path}")

            # Track cleanup action
            self.history.add_action('temp_files_cleaned', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'files_deleted': deleted_count
            })

            # Show confirmation message
            QMessageBox.information(
                self,
                "Cleanup Complete",
                f"Successfully cleaned {deleted_count} temporary data files."
            )

        except Exception as e:
            print(f"Error cleaning temp files: {e}")
            QMessageBox.warning(
                self,
                "Cleanup Warning",
                f"Some files could not be deleted: {str(e)}"
            )

    def handleError(self, error_message):
        # Track error occurrence
        self.history.add_action('error_occurred', {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'error_message': error_message
        })
        QMessageBox.critical(self, "Error", f"Failed to generate report: {error_message}")

    def updateTextAreas(self):
        try:
            if not self.network_info:
                print("No network info available for text areas")
                return

            # Format detailed information for left text area
            print("Formatting detailed info...")
            detailed_info = self.formatDetailedInfo()
            self.left_text_area.setText(detailed_info)

            # Format summary for right text area
            print("Formatting summary info...")
            summary = self.formatSummary()
            self.right_text_area.setText(summary)

            print("Text areas updated successfully")
        except Exception as e:
            print(f"Error updating text areas: {str(e)}")
            self.handleError(f"Failed to update display: {str(e)}")

    def formatDetailedInfo(self):
        network_info = self.network_info
        detailed_info = f"""
Network Administrator Report
Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

System Information:
------------------
Platform: {network_info['system']['platform']} {network_info['system']['platform_release']}
Version: {network_info['system']['platform_version']}
Architecture: {network_info['system']['architecture']}
Processor: {network_info['system']['processor']}
Hostname: {network_info['system']['hostname']}
IP Address: {network_info['system']['ip_address']}

Network Configuration:
--------------------
Default Gateway: {network_info['default_gateway']}

IP Addresses:"""

        for ip_info in network_info['ip_addresses']:
            detailed_info += f"\nInterface: {ip_info['interface']}"
            detailed_info += f"\nIP: {ip_info['ip']}"
            detailed_info += f"\nNetmask: {ip_info['netmask']}"
            detailed_info += f"\nBroadcast: {ip_info['broadcast']}\n"

        detailed_info += "\nNetwork Interfaces:"
        for interface, stats in network_info['interfaces'].items():
            detailed_info += f"\n\n{interface}:"
            detailed_info += f"\nSpeed: {stats['speed']}MB/s"
            detailed_info += f"\nMTU: {stats['mtu']}"
            detailed_info += f"\nIs Up: {stats['isup']}"
            detailed_info += f"\nDuplex: {stats['duplex']}"
            detailed_info += f"\nFlags: {stats['flags']}"

        detailed_info += "\n\nActive Network Connections:"
        for conn in network_info['connections']:
            detailed_info += f"\n\nConnection:"
            detailed_info += f"\nFamily: {conn['family']}"
            detailed_info += f"\nType: {conn['type']}"
            detailed_info += f"\nLocal Address: {conn['local_addr']}"
            detailed_info += f"\nRemote Address: {conn['remote_addr']}"
            detailed_info += f"\nStatus: {conn['status']}"
            detailed_info += f"\nPID: {conn['pid']}"

        # Add user interaction history
        detailed_info += "\n\nUser Interaction History:\n"
        detailed_info += "-------------------------\n"
        history_entries = self.history.get_actions()
        if history_entries and isinstance(history_entries, list) and len(history_entries) > 0:
            # Sort by timestamp
            try:
                sorted_entries = sorted(history_entries, key=lambda x: x.get('timestamp', '') if isinstance(x, dict) else '')
                for entry in sorted_entries[-10:]:  # Show last 10 entries
                    if isinstance(entry, dict):
                        action_type = entry.get('action_type', 'Unknown')
                        timestamp = entry.get('timestamp', 'Unknown')
                        detailed_info += f"{timestamp}: {action_type}\n"
            except Exception as e:
                print(f"Error formatting history in detailed info: {e}")
                detailed_info += f"Error formatting history: {str(e)}\n"
        else:
            detailed_info += "No history available\n"

        # Track which modules the user has interacted with
        used_modules = set()
        for entry in history_entries:
            if isinstance(entry, dict):
                action_type = entry.get('action_type', '')
                if 'packet' in action_type.lower():
                    used_modules.add('packet_analysis')
                if 'wifi' in action_type.lower():
                    used_modules.add('wifi_scanner')
                if 'device' in action_type.lower() or 'scan' in action_type.lower():
                    used_modules.add('network_device_scan')
                if 'troubleshoot' in action_type.lower():
                    used_modules.add('network_troubleshoot')
                if 'monitor' in action_type.lower():
                    used_modules.add('monitoring')

        # Add packet analysis data if available and used
        if hasattr(self, 'packet_analysis_data') and self.packet_analysis_data and ('packet_analysis' in used_modules or not used_modules):
            detailed_info += "\n\nPacket Analysis:\n"
            detailed_info += "----------------\n"

            # Check if packet_analysis_data is a dictionary
            if isinstance(self.packet_analysis_data, dict):
                # Direct access to top-level stats
                if 'total_packets' in self.packet_analysis_data:
                    detailed_info += f"Total Packets: {self.packet_analysis_data.get('total_packets', 0)}\n"
                if 'tcp_packets' in self.packet_analysis_data:
                    detailed_info += f"TCP Packets: {self.packet_analysis_data.get('tcp_packets', 0)}\n"
                if 'udp_packets' in self.packet_analysis_data:
                    detailed_info += f"UDP Packets: {self.packet_analysis_data.get('udp_packets', 0)}\n"
                if 'icmp_packets' in self.packet_analysis_data:
                    detailed_info += f"ICMP Packets: {self.packet_analysis_data.get('icmp_packets', 0)}\n"
                if 'total_bytes' in self.packet_analysis_data:
                    detailed_info += f"Total Bytes: {self.packet_analysis_data.get('total_bytes', 0) / (1024*1024):.2f} MB\n"

                # Check for nested statistics structure
                if 'statistics' in self.packet_analysis_data and isinstance(self.packet_analysis_data['statistics'], dict):
                    stats = self.packet_analysis_data['statistics']
                    if 'total_packets' in stats:
                        detailed_info += f"Total Packets: {stats.get('total_packets', 0)}\n"
                    if 'tcp_packets' in stats:
                        detailed_info += f"TCP Packets: {stats.get('tcp_packets', 0)}\n"
                    if 'udp_packets' in stats:
                        detailed_info += f"UDP Packets: {stats.get('udp_packets', 0)}\n"
                    if 'icmp_packets' in stats:
                        detailed_info += f"ICMP Packets: {stats.get('icmp_packets', 0)}\n"
                    if 'total_bytes' in stats:
                        detailed_info += f"Total Bytes: {stats.get('total_bytes', 0) / (1024*1024):.2f} MB\n"
            elif isinstance(self.packet_analysis_data, list):
                # If it's a list, just show the count
                detailed_info += f"Total Packets: {len(self.packet_analysis_data)}\n"
                detailed_info += "(Detailed packet information available)\n"

        # Add WiFi scanner data if available and used
        if hasattr(self, 'wifi_scanner_data') and self.wifi_scanner_data and ('wifi_scanner' in used_modules or not used_modules):
            detailed_info += "\n\nWiFi Networks:\n"
            detailed_info += "-------------\n"

            # Check if wifi_scanner_data is a dictionary
            if isinstance(self.wifi_scanner_data, dict):
                networks = self.wifi_scanner_data.get('networks', [])
                if isinstance(networks, list) and networks:
                    for i, network in enumerate(networks[:5]):  # Show top 5 networks
                        if isinstance(network, dict):
                            ssid = network.get('ssid', 'Unknown')
                            signal = network.get('signal_strength', 'Unknown')
                            security = network.get('security', 'Unknown')
                            detailed_info += f"{i+1}. {ssid} - Signal: {signal} - Security: {security}\n"
            # If wifi_scanner_data is a list, assume it's a list of networks
            elif isinstance(self.wifi_scanner_data, list):
                networks = self.wifi_scanner_data
                for i, network in enumerate(networks[:5]):  # Show top 5 networks
                    if isinstance(network, dict):
                        ssid = network.get('SSID', network.get('ssid', 'Unknown'))
                        signal = network.get('Signal', network.get('signal_strength', 'Unknown'))
                        security = network.get('Security', network.get('security', 'Unknown'))
                        detailed_info += f"{i+1}. {ssid} - Signal: {signal} - Security: {security}\n"

        # Add network device scan data if available and used
        if hasattr(self, 'network_device_scan_data') and self.network_device_scan_data and ('network_device_scan' in used_modules or not used_modules):
            detailed_info += "\n\nNetwork Devices:\n"
            detailed_info += "----------------\n"

            # Check if network_device_scan_data is a dictionary
            if isinstance(self.network_device_scan_data, dict):
                # Try to get devices from different possible structures
                devices = None
                if 'devices' in self.network_device_scan_data:
                    devices = self.network_device_scan_data.get('devices', [])
                elif 'results' in self.network_device_scan_data:
                    results = self.network_device_scan_data.get('results', {})
                    if isinstance(results, dict) and 'online_devices' in results:
                        devices = results.get('online_devices', [])
                    elif isinstance(results, dict) and 'devices' in results:
                        devices = results.get('devices', [])

                if isinstance(devices, list) and devices:
                    for i, device in enumerate(devices[:5]):  # Show top 5 devices
                        if isinstance(device, dict):
                            ip = device.get('ip', device.get('IP', 'Unknown'))
                            hostname = device.get('hostname', device.get('Hostname', 'Unknown'))
                            mac = device.get('mac', device.get('MAC', 'Unknown'))
                            detailed_info += f"{i+1}. {hostname} - IP: {ip} - MAC: {mac}\n"
                        elif isinstance(device, str):
                            # Handle case where device is just a string (IP or hostname)
                            detailed_info += f"{i+1}. {device}\n"
            # If network_device_scan_data is a list, assume it's a list of devices or IPs
            elif isinstance(self.network_device_scan_data, list):
                devices = self.network_device_scan_data
                for i, device in enumerate(devices[:5]):  # Show top 5 devices
                    if isinstance(device, dict):
                        ip = device.get('ip', device.get('IP', 'Unknown'))
                        hostname = device.get('hostname', device.get('Hostname', 'Unknown'))
                        mac = device.get('mac', device.get('MAC', 'Unknown'))
                        detailed_info += f"{i+1}. {hostname} - IP: {ip} - MAC: {mac}\n"
                    elif isinstance(device, str):
                        # Handle case where device is just a string (IP or hostname)
                        detailed_info += f"{i+1}. {device}\n"

        # Add network troubleshoot data if available and used
        if hasattr(self, 'network_troubleshoot_data') and self.network_troubleshoot_data and ('network_troubleshoot' in used_modules or not used_modules):
            detailed_info += "\n\nTroubleshooting History:\n"
            detailed_info += "------------------------\n"

            # Handle different possible data structures
            if isinstance(self.network_troubleshoot_data, list):
                # Direct list of troubleshooting entries
                entries = self.network_troubleshoot_data
                # Show last 5 entries
                for i, entry in enumerate(entries[-5:] if len(entries) > 5 else entries):
                    if isinstance(entry, dict):
                        timestamp = entry.get('timestamp', 'Unknown')
                        action = entry.get('action_type', entry.get('type', 'Unknown'))
                        result = entry.get('result', entry.get('status', 'Unknown'))
                        detailed_info += f"{i+1}. {timestamp} - {action} - Result: {result}\n"
                    elif isinstance(entry, str):
                        # Handle case where entry is just a string
                        detailed_info += f"{i+1}. {entry}\n"
            elif isinstance(self.network_troubleshoot_data, dict):
                # Handle case where data is a dictionary with entries
                if 'history' in self.network_troubleshoot_data and isinstance(self.network_troubleshoot_data['history'], list):
                    entries = self.network_troubleshoot_data['history']
                    # Show last 5 entries
                    for i, entry in enumerate(entries[-5:] if len(entries) > 5 else entries):
                        if isinstance(entry, dict):
                            timestamp = entry.get('timestamp', 'Unknown')
                            action = entry.get('action_type', entry.get('type', 'Unknown'))
                            result = entry.get('result', entry.get('status', 'Unknown'))
                            detailed_info += f"{i+1}. {timestamp} - {action} - Result: {result}\n"
                        elif isinstance(entry, str):
                            # Handle case where entry is just a string
                            detailed_info += f"{i+1}. {entry}\n"
                else:
                    # Just show the dictionary keys as a summary
                    detailed_info += "Troubleshooting data available with the following information:\n"
                    for key in self.network_troubleshoot_data.keys():
                        detailed_info += f"- {key}\n"

        return detailed_info

    def formatSummary(self):
        network_info = self.network_info
        summary = f"""
Network Summary Report
Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

System Overview:
--------------
Platform: {network_info['system']['platform']} {network_info['system']['platform_release']}
Hostname: {network_info['system']['hostname']}
IP Address: {network_info['system']['ip_address']}
Default Gateway: {network_info['default_gateway']}

Network Statistics:
-----------------
Total Network Interfaces: {len(network_info['interfaces'])}
Active IP Addresses: {len(network_info['ip_addresses'])}
Active Connections: {len(network_info['connections'])}

Network Performance:
------------------
Bytes Sent: {network_info['io_stats'].bytes_sent / (1024*1024):.2f} MB
Bytes Received: {network_info['io_stats'].bytes_recv / (1024*1024):.2f} MB
Packets Sent: {network_info['io_stats'].packets_sent}
Packets Received: {network_info['io_stats'].packets_recv}
"""
        if isinstance(network_info['speed_test'], dict):
            summary += f"""
Speed Test Results:
------------------
Download Speed: {network_info['speed_test']['download_speed']:.2f} Mbps
Upload Speed: {network_info['speed_test']['upload_speed']:.2f} Mbps
Ping: {network_info['speed_test']['ping']:.2f} ms
"""
        else:
            summary += "\nSpeed Test: Not available"

        # Add user interaction summary
        summary += "\n\nUser Activity Summary:\n"
        summary += "---------------------\n"
        history_entries = self.history.get_actions()
        if history_entries and isinstance(history_entries, list) and len(history_entries) > 0:
            try:
                # Count actions by type
                action_counts = {}
                for entry in history_entries:
                    if isinstance(entry, dict):
                        action_type = entry.get('action_type', 'Unknown')
                        action_counts[action_type] = action_counts.get(action_type, 0) + 1

                # Show counts of different actions
                for action, count in action_counts.items():
                    summary += f"{action}: {count} times\n"

                # Show first and last activity timestamps
                sorted_entries = sorted(history_entries, key=lambda x: x.get('timestamp', '') if isinstance(x, dict) else '')
                if sorted_entries:
                    first_entry = sorted_entries[0]
                    last_entry = sorted_entries[-1]
                    if isinstance(first_entry, dict) and isinstance(last_entry, dict):
                        summary += f"First activity: {first_entry.get('timestamp', 'Unknown')}\n"
                        summary += f"Latest activity: {last_entry.get('timestamp', 'Unknown')}\n"
            except Exception as e:
                print(f"Error formatting history in summary: {e}")
                summary += f"Error formatting history: {str(e)}\n"
        else:
            summary += "No user activity recorded\n"

        # Add packet analysis summary if available
        if hasattr(self, 'packet_analysis_data') and self.packet_analysis_data:
            summary += "\n\nPacket Analysis Summary:\n"
            summary += "-----------------------\n"

            # Handle different data structures
            if isinstance(self.packet_analysis_data, dict):
                # Try to get packet stats from top level or nested 'statistics' key
                stats = self.packet_analysis_data
                if 'statistics' in self.packet_analysis_data and isinstance(self.packet_analysis_data['statistics'], dict):
                    stats = self.packet_analysis_data['statistics']

                # Get total packets
                total_packets = stats.get('total_packets', 0)
                if total_packets > 0:
                    summary += f"Total Packets: {total_packets}\n"

                    # Calculate percentages for different packet types
                    tcp_packets = stats.get('tcp_packets', 0)
                    udp_packets = stats.get('udp_packets', 0)
                    icmp_packets = stats.get('icmp_packets', 0)

                    if tcp_packets > 0:
                        tcp_percent = (tcp_packets / total_packets) * 100
                        summary += f"TCP Traffic: {tcp_percent:.1f}%\n"
                    if udp_packets > 0:
                        udp_percent = (udp_packets / total_packets) * 100
                        summary += f"UDP Traffic: {udp_percent:.1f}%\n"
                    if icmp_packets > 0:
                        icmp_percent = (icmp_packets / total_packets) * 100
                        summary += f"ICMP Traffic: {icmp_percent:.1f}%\n"
                else:
                    # Just show what keys are available in the data
                    summary += "Packet analysis data available with the following information:\n"
                    for key in stats.keys():
                        summary += f"- {key}\n"
            elif isinstance(self.packet_analysis_data, list):
                # If it's a list, just show the count
                summary += f"Total Packets: {len(self.packet_analysis_data)}\n"
                summary += "(Detailed packet information available)\n"

        # Add WiFi scanner summary if available
        if hasattr(self, 'wifi_scanner_data') and self.wifi_scanner_data:
            summary += "\n\nWiFi Networks Summary:\n"
            summary += "---------------------\n"

            # Handle different data structures
            if isinstance(self.wifi_scanner_data, dict):
                networks = self.wifi_scanner_data.get('networks', [])
                if isinstance(networks, list):
                    summary += f"Total Networks Detected: {len(networks)}\n"
                    # Count security types
                    security_types = {}
                    for network in networks:
                        if isinstance(network, dict):
                            security = network.get('security', 'Unknown')
                            security_types[security] = security_types.get(security, 0) + 1
                    for security, count in security_types.items():
                        summary += f"{security}: {count} networks\n"
                else:
                    # Just show what keys are available in the data
                    summary += "WiFi data available with the following information:\n"
                    for key in self.wifi_scanner_data.keys():
                        summary += f"- {key}\n"
            elif isinstance(self.wifi_scanner_data, list):
                # If it's a list, assume it's a list of networks
                summary += f"Total Networks Detected: {len(self.wifi_scanner_data)}\n"
                # Count security types
                security_types = {}
                for network in self.wifi_scanner_data:
                    if isinstance(network, dict):
                        security = network.get('Security', network.get('security', 'Unknown'))
                        security_types[security] = security_types.get(security, 0) + 1
                for security, count in security_types.items():
                    summary += f"{security}: {count} networks\n"

        # Add network device scan summary if available
        if hasattr(self, 'network_device_scan_data') and self.network_device_scan_data:
            summary += "\n\nNetwork Devices Summary:\n"
            summary += "------------------------\n"

            # Handle different data structures
            if isinstance(self.network_device_scan_data, dict):
                # Try to get devices from different possible structures
                devices = None
                if 'devices' in self.network_device_scan_data:
                    devices = self.network_device_scan_data.get('devices', [])
                elif 'results' in self.network_device_scan_data:
                    results = self.network_device_scan_data.get('results', {})
                    if isinstance(results, dict) and 'online_devices' in results:
                        devices = results.get('online_devices', [])
                    elif isinstance(results, dict) and 'devices' in results:
                        devices = results.get('devices', [])

                if isinstance(devices, list):
                    summary += f"Total Devices Detected: {len(devices)}\n"

                    # Count device types if available
                    device_types = {}
                    for device in devices:
                        if isinstance(device, dict):
                            device_type = device.get('type', device.get('device_type', 'Unknown'))
                            device_types[device_type] = device_types.get(device_type, 0) + 1
                    for device_type, count in device_types.items():
                        if device_type != 'Unknown':
                            summary += f"{device_type}: {count} devices\n"
                else:
                    # Just show what keys are available in the data
                    summary += "Network device data available with the following information:\n"
                    for key in self.network_device_scan_data.keys():
                        summary += f"- {key}\n"
            elif isinstance(self.network_device_scan_data, list):
                # If it's a list, assume it's a list of devices
                summary += f"Total Devices Detected: {len(self.network_device_scan_data)}\n"

                # Count device types if available
                device_types = {}
                for device in self.network_device_scan_data:
                    if isinstance(device, dict):
                        device_type = device.get('type', device.get('device_type', 'Unknown'))
                        device_types[device_type] = device_types.get(device_type, 0) + 1
                for device_type, count in device_types.items():
                    if device_type != 'Unknown':
                        summary += f"{device_type}: {count} devices\n"

        # Add troubleshooting summary if available
        if hasattr(self, 'network_troubleshoot_data') and self.network_troubleshoot_data:
            summary += "\n\nTroubleshooting Summary:\n"
            summary += "------------------------\n"

            # Handle different data structures
            if isinstance(self.network_troubleshoot_data, list):
                # Direct list of troubleshooting entries
                entries = self.network_troubleshoot_data
                summary += f"Total Troubleshooting Actions: {len(entries)}\n"

                if entries:
                    # Find the latest entry
                    latest_entry = None
                    for entry in reversed(entries):
                        if isinstance(entry, dict):
                            latest_entry = entry
                            break

                    if latest_entry:
                        timestamp = latest_entry.get('timestamp', 'Unknown')
                        action = latest_entry.get('action_type', latest_entry.get('type', 'Unknown'))
                        summary += f"Latest Action: {action} at {timestamp}\n"

                    # Count action types
                    action_types = {}
                    for entry in entries:
                        if isinstance(entry, dict):
                            action_type = entry.get('action_type', entry.get('type', 'Unknown'))
                            action_types[action_type] = action_types.get(action_type, 0) + 1
                    for action_type, count in action_types.items():
                        summary += f"{action_type}: {count} times\n"
            elif isinstance(self.network_troubleshoot_data, dict):
                # Handle case where data is a dictionary with entries
                if 'history' in self.network_troubleshoot_data and isinstance(self.network_troubleshoot_data['history'], list):
                    entries = self.network_troubleshoot_data['history']
                    summary += f"Total Troubleshooting Actions: {len(entries)}\n"

                    if entries:
                        # Find the latest entry
                        latest_entry = None
                        for entry in reversed(entries):
                            if isinstance(entry, dict):
                                latest_entry = entry
                                break

                        if latest_entry:
                            timestamp = latest_entry.get('timestamp', 'Unknown')
                            action = latest_entry.get('action_type', latest_entry.get('type', 'Unknown'))
                            summary += f"Latest Action: {action} at {timestamp}\n"

                        # Count action types
                        action_types = {}
                        for entry in entries:
                            if isinstance(entry, dict):
                                action_type = entry.get('action_type', entry.get('type', 'Unknown'))
                                action_types[action_type] = action_types.get(action_type, 0) + 1
                        for action_type, count in action_types.items():
                            summary += f"{action_type}: {count} times\n"
                else:
                    # Just show what keys are available in the data
                    summary += "Troubleshooting data available with the following information:\n"
                    for key in self.network_troubleshoot_data.keys():
                        summary += f"- {key}\n"

        return summary

    def saveReportAsPDF(self, is_final_report=False):
        if not self.network_info:
            QMessageBox.warning(self, "Warning", "No network information available to save.")
            return

        # For final reports, just use the existing data without re-running tests
        if is_final_report:
            # Show a progress dialog while preparing the report
            refresh_progress = QProgressDialog("Preparing comprehensive report from existing data...", None, 0, 100, self)
            refresh_progress.setWindowModality(Qt.WindowModality.WindowModal)
            refresh_progress.setAutoClose(True)
            refresh_progress.setValue(10)
            refresh_progress.show()

            # Add a record of this comprehensive report generation
            self.history.add_action('comprehensive_report_generation', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'is_final_report': is_final_report
            })
            refresh_progress.setValue(100)

        try:
            # Set default save location to project root folder
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_filename = os.path.join(script_dir, "Final_Network_Report.pdf" if is_final_report else "Network_Report.pdf")

            # Get save location from user with default in project root
            file_name, _ = QFileDialog.getSaveFileName(
                self,
                "Save Network Report",
                default_filename,
                "PDF Files (*.pdf)"
            )

            if file_name:
                # Track PDF save attempt
                self.history.add_action('pdf_save_started', {
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'file_name': file_name
                })

                # Show progress dialog
                self.progress_dialog = QProgressDialog("Generating PDF Report...", None, 0, 100, self)
                self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
                self.progress_dialog.setAutoClose(True)
                self.progress_dialog.show()

                # Create PDF document
                doc = SimpleDocTemplate(file_name, pagesize=letter)
                styles = getSampleStyleSheet()
                title_style = styles['Heading1']
                heading_style = styles['Heading2']
                normal_style = styles['Normal']

                # Create content
                content = []

                # Add title
                if is_final_report:
                    content.append(Paragraph("FINAL COMPREHENSIVE NETWORK ANALYSIS REPORT", title_style))
                    content.append(Spacer(1, 6))
                    content.append(Paragraph("Complete Test Results and Network Analysis", heading_style))
                else:
                    content.append(Paragraph("Comprehensive Network Analysis Report", title_style))
                content.append(Spacer(1, 12))

                # Add timestamp
                content.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
                content.append(Spacer(1, 12))

                # Add report type description
                if is_final_report:
                    content.append(Paragraph("This is a final comprehensive report containing all test details and network analysis results collected during this session.", normal_style))
                    content.append(Spacer(1, 12))

                # Get network information
                network_info = self.network_info

                # Add system information
                content.append(Paragraph("System Information", heading_style))
                content.append(Spacer(1, 6))

                system_info = network_info['system']
                system_data = [
                    ["Platform", f"{system_info['platform']} {system_info['platform_release']}"],
                    ["Version", system_info['platform_version']],
                    ["Architecture", system_info['architecture']],
                    ["Processor", system_info['processor']],
                    ["Hostname", system_info['hostname']],
                    ["IP Address", system_info['ip_address']]
                ]

                system_table = Table(system_data, colWidths=[2*inch, 4*inch])
                system_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(system_table)
                content.append(Spacer(1, 12))

                # Add hardware information
                content.append(Paragraph("Hardware Information", heading_style))
                content.append(Spacer(1, 6))

                # Get CPU information
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                cpu_freq = psutil.cpu_freq()
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                hardware_data = [
                    ["Component", "Details"],
                    ["CPU Usage", f"{cpu_percent}%"],
                    ["CPU Cores", str(cpu_count)],
                    ["CPU Frequency", f"{cpu_freq.current:.2f} MHz"],
                    ["Memory Total", f"{memory.total / (1024**3):.2f} GB"],
                    ["Memory Used", f"{memory.used / (1024**3):.2f} GB"],
                    ["Memory Free", f"{memory.free / (1024**3):.2f} GB"],
                    ["Disk Total", f"{disk.total / (1024**3):.2f} GB"],
                    ["Disk Used", f"{disk.used / (1024**3):.2f} GB"],
                    ["Disk Free", f"{disk.free / (1024**3):.2f} GB"]
                ]

                hardware_table = Table(hardware_data, colWidths=[2*inch, 2*inch])
                hardware_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(hardware_table)
                content.append(Spacer(1, 12))

                # Add network interfaces
                content.append(Paragraph("Network Interfaces", heading_style))
                content.append(Spacer(1, 6))

                interface_data = [["Interface", "IP Address", "Netmask", "Speed", "MTU", "Status"]]
                for interface, stats in network_info['interfaces'].items():
                    ip_info = next((ip for ip in network_info['ip_addresses'] if ip['interface'] == interface), None)
                    interface_data.append([
                        interface,
                        ip_info['ip'] if ip_info else "N/A",
                        ip_info['netmask'] if ip_info else "N/A",
                        f"{stats['speed']}MB/s",
                        str(stats['mtu']),
                        "Up" if stats['isup'] else "Down"
                    ])

                interface_table = Table(interface_data, colWidths=[1.2*inch, 1.5*inch, 1.5*inch, 1*inch, 0.8*inch, 0.8*inch])
                interface_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(interface_table)
                content.append(Spacer(1, 12))

                # Add network protocols and connections
                content.append(Paragraph("Active Network Connections", heading_style))
                content.append(Spacer(1, 6))

                connection_data = [["Protocol", "Local Address", "Remote Address", "Status"]]
                for conn in network_info['connections']:
                    protocol = "TCP" if conn['type'] == socket.SOCK_STREAM else "UDP"
                    local_addr = f"{conn['local_addr'][0]}:{conn['local_addr'][1]}" if conn['local_addr'] else "N/A"
                    remote_addr = f"{conn['remote_addr'][0]}:{conn['remote_addr'][1]}" if conn['remote_addr'] else "N/A"
                    connection_data.append([protocol, local_addr, remote_addr, conn['status']])

                connection_table = Table(connection_data, colWidths=[1*inch, 2*inch, 2*inch, 1*inch])
                connection_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(connection_table)
                content.append(Spacer(1, 12))

                # Add user interaction history
                content.append(Paragraph("User Interaction History", heading_style))
                content.append(Spacer(1, 6))

                # Get user history
                history_entries = self.history.get_actions()
                if history_entries and isinstance(history_entries, list) and len(history_entries) > 0:
                    try:
                        # Sort by timestamp
                        sorted_entries = sorted(history_entries, key=lambda x: x.get('timestamp', '') if isinstance(x, dict) else '')

                        # Create history table
                        history_data = [["Timestamp", "Action"]]
                        for entry in sorted_entries[-10:]:  # Show last 10 entries
                            if isinstance(entry, dict):
                                action_type = entry.get('action_type', 'Unknown')
                                timestamp = entry.get('timestamp', 'Unknown')
                                history_data.append([timestamp, action_type])
                    except Exception as e:
                        print(f"Error formatting history in PDF: {e}")
                        history_data = [["Timestamp", "Action"], ["Error", f"Failed to format history: {str(e)}"]]
                else:
                    history_data = [["Timestamp", "Action"], ["No Data", "No history available"]]

                history_table = Table(history_data, colWidths=[2.5*inch, 3.5*inch])
                history_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(history_table)

                content.append(Spacer(1, 12))

                # Add network performance
                content.append(Paragraph("Network Performance", heading_style))
                content.append(Spacer(1, 6))

                io_stats = network_info['io_stats']
                performance_data = [
                    ["Metric", "Value"],
                    ["Bytes Sent", f"{io_stats.bytes_sent / (1024*1024):.2f} MB"],
                    ["Bytes Received", f"{io_stats.bytes_recv / (1024*1024):.2f} MB"],
                    ["Packets Sent", str(io_stats.packets_sent)],
                    ["Packets Received", str(io_stats.packets_recv)],
                    ["Errors In", str(io_stats.errin)],
                    ["Errors Out", str(io_stats.errout)],
                    ["Drops In", str(io_stats.dropin)],
                    ["Drops Out", str(io_stats.dropout)]
                ]

                if isinstance(network_info['speed_test'], dict):
                    speed_test = network_info['speed_test']
                    performance_data.extend([
                        ["Download Speed", f"{speed_test['download_speed']:.2f} Mbps"],
                        ["Upload Speed", f"{speed_test['upload_speed']:.2f} Mbps"],
                        ["Ping", f"{speed_test['ping']:.2f} ms"]
                    ])

                performance_table = Table(performance_data, colWidths=[2*inch, 2*inch])
                performance_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(performance_table)

                # Add packet analysis data if available
                if self.packet_analysis_data:
                    content.append(Paragraph("Network Packet Analysis", heading_style))
                    content.append(Spacer(1, 6))

                    # Extract packet statistics
                    packet_stats = []
                    packet_stats.append(["Metric", "Value"])

                    if 'total_packets' in self.packet_analysis_data:
                        packet_stats.append(["Total Packets", str(self.packet_analysis_data.get('total_packets', 0))])
                    if 'tcp_packets' in self.packet_analysis_data:
                        packet_stats.append(["TCP Packets", str(self.packet_analysis_data.get('tcp_packets', 0))])
                    if 'udp_packets' in self.packet_analysis_data:
                        packet_stats.append(["UDP Packets", str(self.packet_analysis_data.get('udp_packets', 0))])
                    if 'icmp_packets' in self.packet_analysis_data:
                        packet_stats.append(["ICMP Packets", str(self.packet_analysis_data.get('icmp_packets', 0))])
                    if 'total_bytes' in self.packet_analysis_data:
                        packet_stats.append(["Total Bytes", f"{self.packet_analysis_data.get('total_bytes', 0) / (1024*1024):.2f} MB"])

                    # Create packet statistics table
                    if len(packet_stats) > 1:  # Only create table if we have data
                        packet_table = Table(packet_stats, colWidths=[2*inch, 2*inch])
                        packet_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        content.append(packet_table)
                    else:
                        content.append(Paragraph("No detailed packet statistics available", normal_style))

                    content.append(Spacer(1, 12))

                # Add WiFi scanner data if available
                if self.wifi_scanner_data:
                    content.append(Paragraph("WiFi Networks", heading_style))
                    content.append(Spacer(1, 6))

                    # Extract WiFi networks
                    wifi_data = []
                    wifi_data.append(["SSID", "Signal Strength", "Security", "Channel"])

                    # Check if we have a list of networks
                    networks = self.wifi_scanner_data.get('networks', [])
                    if isinstance(networks, list) and networks:
                        for network in networks[:10]:  # Limit to 10 networks to keep report manageable
                            ssid = network.get('ssid', 'Unknown')
                            signal = network.get('signal_strength', 'Unknown')
                            security = network.get('security', 'Unknown')
                            channel = network.get('channel', 'Unknown')
                            wifi_data.append([ssid, signal, security, channel])

                    # Create WiFi networks table
                    if len(wifi_data) > 1:  # Only create table if we have data
                        wifi_table = Table(wifi_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
                        wifi_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        content.append(wifi_table)
                    else:
                        content.append(Paragraph("No WiFi networks data available", normal_style))

                    content.append(Spacer(1, 12))

                # Add network device scan data if available
                if self.network_device_scan_data:
                    content.append(Paragraph("Network Devices", heading_style))
                    content.append(Spacer(1, 6))

                    # Extract device data
                    device_data = []
                    device_data.append(["IP Address", "Hostname", "MAC Address", "Status"])

                    # Check if we have a list of devices
                    devices = self.network_device_scan_data.get('devices', [])
                    if isinstance(devices, list) and devices:
                        for device in devices[:15]:  # Limit to 15 devices
                            ip = device.get('ip', 'Unknown')
                            hostname = device.get('hostname', 'Unknown')
                            mac = device.get('mac', 'Unknown')
                            status = device.get('status', 'Unknown')
                            device_data.append([ip, hostname, mac, status])

                    # Create devices table
                    if len(device_data) > 1:  # Only create table if we have data
                        device_table = Table(device_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
                        device_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        content.append(device_table)
                    else:
                        content.append(Paragraph("No network device data available", normal_style))

                    content.append(Spacer(1, 12))

                # Add network troubleshoot data if available
                if self.network_troubleshoot_data:
                    content.append(Paragraph("Network Troubleshooting History", heading_style))
                    content.append(Spacer(1, 6))

                    # Extract troubleshooting history
                    trouble_data = []
                    trouble_data.append(["Timestamp", "Action", "Details"])

                    # Check if we have a list of history entries
                    if isinstance(self.network_troubleshoot_data, list):
                        for entry in self.network_troubleshoot_data[-10:]:  # Get last 10 entries
                            if isinstance(entry, dict):
                                timestamp = entry.get('timestamp', 'Unknown')
                                action = entry.get('action_type', 'Unknown')
                                details = str(entry.get('details', {})).replace('{', '').replace('}', '')[:50]  # Truncate details
                                trouble_data.append([timestamp, action, details])

                    # Create troubleshooting table
                    if len(trouble_data) > 1:  # Only create table if we have data
                        trouble_table = Table(trouble_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
                        trouble_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        content.append(trouble_table)
                    else:
                        content.append(Paragraph("No troubleshooting history available", normal_style))

                    content.append(Spacer(1, 12))

                # Add comprehensive test details section if this is a final report
                if is_final_report:
                    content.append(Paragraph("ALL TEST DETAILS", heading_style))
                    content.append(Spacer(1, 6))
                    content.append(Paragraph("This section contains detailed information about all tests run during this session.", normal_style))
                    content.append(Spacer(1, 12))

                    # Get all user actions related to tests
                    test_actions = []
                    history_entries = self.history.get_actions()
                    if history_entries and isinstance(history_entries, list):
                        for entry in history_entries:
                            if isinstance(entry, dict):
                                action_type = entry.get('action_type', '')
                                if isinstance(action_type, str) and any(test_type in action_type for test_type in ['test', 'scan', 'analysis', 'monitor', 'troubleshoot']):
                                    test_actions.append(entry)

                    if test_actions:
                        # Sort by timestamp
                        test_actions = sorted(test_actions, key=lambda x: x.get('timestamp', ''))

                        # Create a table of all test actions
                        test_table_data = [["Timestamp", "Test Type", "Details"]]
                        for action in test_actions:
                            timestamp = action.get('timestamp', 'Unknown')
                            test_type = action.get('action_type', 'Unknown')
                            details = str(action.get('details', {})).replace('{', '').replace('}', '')[:50]  # Truncate details
                            test_table_data.append([timestamp, test_type, details])

                        test_table = Table(test_table_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
                        test_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        content.append(test_table)
                        content.append(Spacer(1, 12))
                    else:
                        content.append(Paragraph("No test actions were recorded during this session.", normal_style))
                        content.append(Spacer(1, 12))

                    # Add detailed packet capture analysis if available
                    if self.packet_analysis_data and 'packets' in self.packet_analysis_data:
                        content.append(Paragraph("Detailed Packet Capture Analysis", heading_style))
                        content.append(Spacer(1, 6))

                        packets = self.packet_analysis_data['packets']
                        if isinstance(packets, list) and packets:
                            # Create a table of packet details
                            packet_table_data = [["Time", "Source", "Destination", "Protocol", "Length", "Info"]]
                            for packet in packets[:50]:  # Limit to 50 packets to keep report manageable
                                time = packet.get('time', 'Unknown')
                                source = packet.get('source', 'Unknown')
                                destination = packet.get('destination', 'Unknown')
                                protocol = packet.get('protocol', 'Unknown')
                                length = packet.get('length', 'Unknown')
                                info = packet.get('info', 'Unknown')[:30]  # Truncate info
                                packet_table_data.append([time, source, destination, protocol, length, info])

                            packet_detail_table = Table(packet_table_data, colWidths=[0.8*inch, 1.2*inch, 1.2*inch, 0.8*inch, 0.6*inch, 1.4*inch])
                            packet_detail_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for packet details
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                                ('GRID', (0, 0), (-1, -1), 1, colors.black)
                            ]))
                            content.append(packet_detail_table)
                        else:
                            content.append(Paragraph("No detailed packet data available.", normal_style))
                        content.append(Spacer(1, 12))

                    # Add detailed WiFi scan results if available
                    if isinstance(self.wifi_scanner_data, dict) and 'networks' in self.wifi_scanner_data:
                        content.append(Paragraph("Detailed WiFi Scan Results", heading_style))
                        content.append(Spacer(1, 6))

                        networks = self.wifi_scanner_data['networks']
                        if isinstance(networks, list) and networks:
                            # Create a table with all network details
                            wifi_detail_data = [["SSID", "BSSID", "Signal", "Channel", "Frequency", "Security", "First Seen"]]
                            for network in networks:
                                ssid = network.get('ssid', 'Unknown')
                                bssid = network.get('bssid', 'Unknown')
                                signal = network.get('signal_strength', 'Unknown')
                                channel = network.get('channel', 'Unknown')
                                frequency = network.get('frequency', 'Unknown')
                                security = network.get('security', 'Unknown')
                                first_seen = network.get('first_seen', 'Unknown')
                                wifi_detail_data.append([ssid, bssid, signal, channel, frequency, security, first_seen])

                            wifi_detail_table = Table(wifi_detail_data, colWidths=[1*inch, 1.2*inch, 0.6*inch, 0.6*inch, 0.8*inch, 1*inch, 0.8*inch])
                            wifi_detail_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for detailed table
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                                ('GRID', (0, 0), (-1, -1), 1, colors.black)
                            ]))
                            content.append(wifi_detail_table)
                        else:
                            content.append(Paragraph("No detailed WiFi network data available.", normal_style))
                        content.append(Spacer(1, 12))

                    # Add detailed network device scan results if available
                    if isinstance(self.network_device_scan_data, dict) and 'devices' in self.network_device_scan_data:
                        content.append(Paragraph("Detailed Network Device Scan Results", heading_style))
                        content.append(Spacer(1, 6))

                        devices = self.network_device_scan_data['devices']
                        if isinstance(devices, list) and devices:
                            # Create a table with all device details
                            device_detail_data = [["IP Address", "Hostname", "MAC Address", "Vendor", "Status", "Response Time", "First Seen"]]
                            for device in devices:
                                ip = device.get('ip', 'Unknown')
                                hostname = device.get('hostname', 'Unknown')
                                mac = device.get('mac', 'Unknown')
                                vendor = device.get('vendor', 'Unknown')
                                status = device.get('status', 'Unknown')
                                response_time = device.get('response_time', 'Unknown')
                                first_seen = device.get('first_seen', 'Unknown')
                                device_detail_data.append([ip, hostname, mac, vendor, status, response_time, first_seen])

                            device_detail_table = Table(device_detail_data, colWidths=[1*inch, 1*inch, 1.2*inch, 0.8*inch, 0.6*inch, 0.8*inch, 0.6*inch])
                            device_detail_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for detailed table
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                                ('GRID', (0, 0), (-1, -1), 1, colors.black)
                            ]))
                            content.append(device_detail_table)
                        else:
                            content.append(Paragraph("No detailed network device data available.", normal_style))
                        content.append(Spacer(1, 12))

                # Build PDF
                doc.build(content)
                self.progress_dialog.setValue(100)
                QMessageBox.information(self, "Success", "Report saved successfully!")

                # Ask user if they want to clean temp files
                reply = QMessageBox.question(
                    self,
                    "Clean Temporary Files",
                    "Do you want to clean temporary data files?\n\n"
                    "This will remove all saved data from your previous analysis sessions.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.Yes:
                    self.clean_temp_files()

                # Track successful PDF save
                self.history.add_action('pdf_save_complete', {
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'file_name': file_name
                })

        except Exception as e:
            # Track PDF save error
            self.history.add_action('pdf_save_error', {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error_message': str(e)
            })
            QMessageBox.critical(self, "Error", f"Failed to save PDF: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = SaveInterface()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
