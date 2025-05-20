import sys
import socket
import subprocess
import threading
import platform
import json
import os
import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
                             QFrame, QProgressBar, QScrollArea, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt6.QtGui import QColor, QPalette, QLinearGradient, QFont, QGradient
import requests
import ssl
import whois
import dns.resolver
import time


class UserHistory:
    def __init__(self):
        # Use a specific path for the data_temp directory
        self.temp_dir = r"C:\Users\kosal\OneDrive - NSBM\Final Year Project\V3\data_temp"
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)
        
        # Set history file path in data_temp directory
        self.history_file = os.path.join(self.temp_dir, 'network_troubleshoot_history.json')
        self.history = self.load_history()

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error loading history: {e}")
            return []

    def save_history(self):
        try:
            # Ensure data_temp directory exists
            if not os.path.exists(self.temp_dir):
                os.makedirs(self.temp_dir)
            
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=4)
        except Exception as e:
            print(f"Error saving history: {e}")

    def add_action(self, action_type, details):
        entry = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action_type': action_type,
            'details': details
        }
        self.history.append(entry)
        self.save_history()

    def clear_history(self):
        self.history = []
        self.save_history()

    def get_history_file_path(self):
        return self.history_file

    def get_temp_dir(self):
        return self.temp_dir


class WorkerSignals(QObject):
    finished = pyqtSignal(str, str)


class Worker(threading.Thread):
    def __init__(self, command, output_type):
        super().__init__()
        self.command = command
        self.output_type = output_type
        self.signals = WorkerSignals()

    def run(self):
        try:
            # Platform-specific command handling
            if platform.system() == "Windows":
                # Use shell=True for Windows
                result = subprocess.run(self.command, capture_output=True, text=True, shell=True)
            else:
                # For Linux/Unix, split the command and use shell=False for better security
                if isinstance(self.command, str):
                    command_list = self.command.split()
                else:
                    command_list = self.command
                result = subprocess.run(command_list, capture_output=True, text=True, shell=False)
            
            output = result.stdout if result.stdout else result.stderr
        except Exception as e:
            output = f"Error executing command: {str(e)}"
        
        self.signals.finished.emit(self.output_type, output)


class GradientLineEdit(QLineEdit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setMinimumHeight(40)
        self.setFont(QFont("Arial", 10))
        self.setStyleSheet("""
            QLineEdit {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                                  stop:0 #e0ffe0, stop:1 #e0e0ff);
                border-radius: 10px;
                padding: 5px 10px;
                border: 1px solid #c0c0c0;
                color: black;
            }
        """)


class GradientTextEdit(QTextEdit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet("""
            QTextEdit {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                                  stop:0 #e0ffe0, stop:1 #e0e0ff);
                border-radius: 10px;
                padding: 5px;
                border: 1px solid #c0c0c0;
                color: black;
            }
        """)


class StyledButton(QPushButton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setMinimumHeight(40)
        self.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.setStyleSheet("""
            QPushButton {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                                  stop:0 #4da6ff, stop:1 #80c6ff);
                color: white;
                border-radius: 15px;
                padding: 5px 15px;
                border: none;
            }
            QPushButton:hover {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                                  stop:0 #3d96ff, stop:1 #70b6ff);
            }
            QPushButton:pressed {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                                  stop:0 #3d86ef, stop:1 #6096ef);
            }
        """)


class NetworkTroubleshooter(QMainWindow):
    def __init__(self):
        super().__init__()
        self.history = UserHistory()
        self.setWindowTitle("Network Troubleshooting")
        self.resize(800, 700)
        
        # Track application start
        self.history.add_action('application_start', {
            'window_title': self.windowTitle(),
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        # Platform-specific styling adjustments
        if platform.system() == "Windows":
            font_family = "Arial"
            mono_font = "Consolas"
        else:
            font_family = "Ubuntu"
            mono_font = "DejaVu Sans Mono"
            
        self.setStyleSheet(f"background-color: #f0f8ff; font-family: {font_family};")
        
        # Create scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #f0f8ff;
            }
            QScrollBar:vertical {
                border: none;
                background: #f0f0f0;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #c0c0c0;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical {
                height: 0px;
            }
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        # Main widget and layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Set the central widget to scroll area and add the main widget to it
        scroll.setWidget(central_widget)
        self.setCentralWidget(scroll)

        # Create a top bar layout for button, title and progress bar
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(0, 0, 0, 0)
        
        # Add Run Analysis button to left side
        self.run_button = StyledButton("Run Analysis")
        self.run_button.clicked.connect(self.run_analysis)
        self.run_button.setFixedWidth(150)  # Set fixed width for button
        top_bar.addWidget(self.run_button)
        
        # Add title in center
        title_label = QLabel("Network Troubleshooting")
        title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: black;")
        top_bar.addWidget(title_label, stretch=1)  # stretch=1 makes it take available space
        
        # Add progress bar to right side
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(200)
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 5px;
                background-color: #e0e0e0;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                              stop:0 #4da6ff, stop:1 #80c6ff);
                border-radius: 5px;
            }
        """)
        self.progress_bar.hide()
        top_bar.addWidget(self.progress_bar)
        
        # Add the top bar layout first
        main_layout.addLayout(top_bar)
        
        # Add spacing after the top bar
        main_layout.addSpacing(20)

        # Website name input
        url_layout = QHBoxLayout()
        url_label = QLabel("Enter Your Website Name")
        url_label.setFont(QFont("Arial", 11))
        url_label.setStyleSheet("color: black;")
        self.url_input = GradientLineEdit()
        self.url_input.setPlaceholderText("e.g., www.google.com")
        url_layout.addWidget(url_label, 1)
        url_layout.addWidget(self.url_input, 2)
        main_layout.addLayout(url_layout)

        # IP Address display
        ip_layout = QHBoxLayout()
        ip_label = QLabel("This is Your Website IP Address")
        ip_label.setFont(QFont("Arial", 11))
        ip_label.setStyleSheet("color: black;")
        self.ip_display = GradientLineEdit()
        self.ip_display.setReadOnly(True)
        self.ip_display.setPlaceholderText("IP Address will appear here")
        ip_layout.addWidget(ip_label, 1)
        ip_layout.addWidget(self.ip_display, 2)
        main_layout.addLayout(ip_layout)

        # Ping output
        ping_label = QLabel("Ping Your Website")
        ping_label.setFont(QFont("Arial", 11))
        ping_label.setStyleSheet("color: black;")
        self.ping_output = GradientTextEdit()
        self.ping_output.setReadOnly(True)
        self.ping_output.setPlaceholderText("Ping results will appear here")
        self.ping_output.setMinimumHeight(100)
        main_layout.addWidget(ping_label)
        main_layout.addWidget(self.ping_output)

        # Traceroute output
        traceroute_label = QLabel("Traceroute Your Website")
        traceroute_label.setFont(QFont("Arial", 11))
        traceroute_label.setStyleSheet("color: black;")
        self.traceroute_output = GradientTextEdit()
        self.traceroute_output.setReadOnly(True)
        self.traceroute_output.setPlaceholderText("Traceroute results will appear here")
        self.traceroute_output.setMinimumHeight(100)
        main_layout.addWidget(traceroute_label)
        main_layout.addWidget(self.traceroute_output)

        # DNS Server details
        dns_label = QLabel("DNS Server Details")
        dns_label.setFont(QFont("Arial", 11))
        dns_label.setStyleSheet("color: black;")
        self.dns_output = GradientTextEdit()
        self.dns_output.setReadOnly(True)
        self.dns_output.setPlaceholderText("DNS lookup results will appear here")
        self.dns_output.setMinimumHeight(100)
        main_layout.addWidget(dns_label)
        main_layout.addWidget(self.dns_output)

        # Website Status
        status_label = QLabel("Website Status & Response")
        status_label.setFont(QFont("Arial", 11))
        status_label.setStyleSheet("color: black;")
        self.status_output = GradientTextEdit()
        self.status_output.setReadOnly(True)
        self.status_output.setPlaceholderText("Website status will appear here")
        self.status_output.setMinimumHeight(100)
        main_layout.addWidget(status_label)
        main_layout.addWidget(self.status_output)

        # SSL Certificate
        ssl_label = QLabel("SSL Certificate Information")
        ssl_label.setFont(QFont("Arial", 11))
        ssl_label.setStyleSheet("color: black;")
        self.ssl_output = GradientTextEdit()
        self.ssl_output.setReadOnly(True)
        self.ssl_output.setPlaceholderText("SSL certificate details will appear here")
        self.ssl_output.setMinimumHeight(100)
        main_layout.addWidget(ssl_label)
        main_layout.addWidget(self.ssl_output)

        # Additional DNS Records
        dns_records_label = QLabel("DNS Records")
        dns_records_label.setFont(QFont("Arial", 11))
        dns_records_label.setStyleSheet("color: black;")
        self.dns_records_output = GradientTextEdit()
        self.dns_records_output.setReadOnly(True)
        self.dns_records_output.setPlaceholderText("DNS records will appear here")
        self.dns_records_output.setMinimumHeight(100)
        main_layout.addWidget(dns_records_label)
        main_layout.addWidget(self.dns_records_output)

        # Store active workers
        self.active_workers = []

    def get_ip_address(self, url):
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
        
        url = url.split('/')[0]
        
        try:
            ip_address = socket.gethostbyname(url)
            return ip_address
        except socket.gaierror:
            return "Could not resolve hostname"

    def run_analysis(self):
        url = self.url_input.text().strip()
        if not url:
            return

        # Track analysis start
        self.history.add_action('analysis_started', {
            'url': url,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

        self.progress_bar.setRange(0, 0)
        self.progress_bar.show()
        
        # Clear all outputs
        self.ip_display.setText("")
        self.ping_output.clear()
        self.traceroute_output.clear()
        self.dns_output.clear()
        self.status_output.clear()
        self.ssl_output.clear()
        self.dns_records_output.clear()
        
        self.run_button.setEnabled(False)

        try:
            # Get IP address
            ip_address = self.get_ip_address(url)
            self.ip_display.setText(ip_address)

            # Track IP resolution
            self.history.add_action('ip_resolved', {
                'url': url,
                'ip_address': ip_address,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

            # Run website status check
            status_info = self.check_website_status(url)
            self.status_output.setText(status_info)

            # Track status check
            self.history.add_action('status_check_complete', {
                'url': url,
                'status_info': status_info,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

            # Get SSL info
            ssl_info = self.get_ssl_info(url)
            self.ssl_output.setText(ssl_info)

            # Track SSL check
            self.history.add_action('ssl_check_complete', {
                'url': url,
                'ssl_info': ssl_info,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

            # Get DNS records
            dns_records = self.get_dns_records(url)
            self.dns_records_output.setText(dns_records)

            # Track DNS records
            self.history.add_action('dns_records_complete', {
                'url': url,
                'dns_records': dns_records,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

            # Run traditional network tests
            system = platform.system().lower()
            if system == 'windows':
                ping_cmd = f"ping -n 4 {url}"
                traceroute_cmd = f"tracert -d {url}"
            else:
                ping_cmd = f"ping -c 4 {url}"
                traceroute_cmd = f"traceroute -n {url}"
            
            nslookup_cmd = f"nslookup {url}"

            self._run_command(ping_cmd, "ping")
            self._run_command(traceroute_cmd, "traceroute")
            self._run_command(nslookup_cmd, "dns")

            # Track analysis completion
            self.history.add_action('analysis_complete', {
                'url': url,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

        except Exception as e:
            # Track analysis error
            self.history.add_action('analysis_error', {
                'url': url,
                'error': str(e),
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")

    def _run_command(self, command, output_type):
        worker = Worker(command, output_type)
        worker.signals.finished.connect(self.update_output)
        self.active_workers.append(worker)
        worker.start()

    def update_output(self, output_type, result):
        if output_type == "ping":
            self.ping_output.setText(result)
            # Track ping results
            self.history.add_action('ping_complete', {
                'output_type': output_type,
                'result': result,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        elif output_type == "traceroute":
            formatted_output = self.format_traceroute_output(result)
            self.traceroute_output.setText(formatted_output)
            # Track traceroute results
            self.history.add_action('traceroute_complete', {
                'output_type': output_type,
                'result': formatted_output,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        elif output_type == "dns":
            self.dns_output.setText(result)
            # Track DNS lookup results
            self.history.add_action('dns_lookup_complete', {
                'output_type': output_type,
                'result': result,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        elif output_type == "status":
            self.status_output.setText(result)
        elif output_type == "ssl":
            self.ssl_output.setText(result)
        elif output_type == "dns_records":
            self.dns_records_output.setText(result)
        
        active_count = sum(1 for w in self.active_workers if w.is_alive())
        if active_count == 0:
            self.progress_bar.hide()
            self.run_button.setEnabled(True)
            self.active_workers = []

    def check_website_status(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            response = requests.get(url, timeout=10)
            return f"Status Code: {response.status_code}\nResponse Time: {response.elapsed.total_seconds():.2f} seconds"
        except requests.RequestException as e:
            return f"Error: {str(e)}"

    def get_ssl_info(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                hostname = url
            else:
                hostname = url.split('://')[1].split('/')[0]
            
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.connect((hostname, 443))
                cert = sock.getpeercert()
                
            return f"""SSL Certificate Info:
Issuer: {dict(x[0] for x in cert['issuer'])}
Valid From: {cert['notBefore']}
Valid Until: {cert['notAfter']}
"""
        except Exception as e:
            return f"SSL Error: {str(e)}"

    def get_dns_records(self, domain):
        try:
            records = []
            record_types = ['A', 'MX', 'NS', 'TXT', 'AAAA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records.append(f"\n{record_type} Records:")
                    for rdata in answers:
                        records.append(f"  {rdata}")
                except Exception:
                    continue
                    
            return "\n".join(records)
        except Exception as e:
            return f"DNS Query Error: {str(e)}"

    def get_whois_info(self, domain):
        try:
            w = whois.whois(domain)
            return f"""Domain Information:
Registrar: {w.registrar}
Creation Date: {w.creation_date}
Expiration Date: {w.expiration_date}
Last Updated: {w.updated_date}
"""
        except Exception as e:
            return f"Whois Error: {str(e)}"

    def scan_common_ports(self, host):
        common_ports = {
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            3306: "MySQL",
            8080: "HTTP-ALT"
        }
        
        results = []
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                results.append(f"Port {port} ({service}): Open")
            sock.close()
        
        return "\n".join(results) if results else "No open ports found"

    def get_ping_command(self, host):
        if platform.system() == "Windows":
            return f"ping -n 4 {host}"
        else:
            return f"ping -c 4 {host}"

    def get_traceroute_command(self, host):
        """
        Get the appropriate traceroute command based on platform with optimized timeouts
        Windows: tracert with reduced wait time and probes
        Linux: traceroute with optimized parameters
        """
        if platform.system() == "Windows":
            # Windows optimizations:
            # -h 15: Maximum hops reduced to 15 (default is 30)
            # -w 500: Wait time of 500ms instead of default 4000ms
            # -d: Prevents DNS lookups to speed up trace
            return f"tracert -h 15 -w 500 -d {host}"
        else:
            # Linux optimizations:
            # -n: No DNS resolution (faster)
            # -w 1: Wait time of 1 second
            # -q 1: Only send one probe per hop (instead of 3)
            # -m 15: Maximum 15 hops (instead of 30)
            # -4: Force IPv4 (typically faster than IPv6)
            return f"traceroute -n -w 1 -q 1 -m 15 -4 {host}"

    def run_traceroute(self):
        """Execute traceroute command with optimized timeout handling"""
        url = self.url_input.text().strip()
        if not url:
            self.traceroute_output.setText("Please enter a valid hostname")
            return

        # Clean the URL
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
        url = url.split('/')[0]  # Remove any path after domain

        # Show progress
        self.traceroute_output.setText("Running traceroute...")
        self.run_button.setEnabled(False)

        # Execute the command with reduced timeout
        command = self.get_traceroute_command(url)
        
        # Create a timer with shorter timeout (15 seconds instead of 30)
        timeout_timer = QTimer()
        timeout_timer.setSingleShot(True)
        timeout_timer.timeout.connect(lambda: self.handle_traceroute_timeout(url))
        timeout_timer.start(15000)  # 15 second overall timeout
        
        worker = Worker(command, "traceroute")
        worker.signals.finished.connect(lambda output_type, result: self.handle_traceroute_result(output_type, result, timeout_timer))
        self.active_workers.append(worker)
        worker.start()

    def handle_traceroute_timeout(self, url):
        """Handle traceroute timeout with more informative message"""
        self.traceroute_output.setText(f"Traceroute to {url} timed out after 15 seconds. Some hops may be missing.")
        self.run_button.setEnabled(True)

    def handle_traceroute_result(self, output_type, result, timeout_timer):
        """Handle traceroute result and cancel timeout timer"""
        timeout_timer.stop()
        self.update_output(output_type, result)
        self.run_button.setEnabled(True)

    def format_traceroute_output(self, output):
        """Format the traceroute output with optimized display"""
        formatted_lines = []
        lines = output.split('\n')
        
        if platform.system() == "Windows":
            for line in lines:
                line = line.strip()
                if line:
                    if "Tracing route" in line:
                        formatted_lines.append(line)
                    elif "Request timed out" in line:
                        parts = [part for part in line.split() if part]
                        if parts:
                            hop_num = parts[0]
                            formatted_lines.append(f"Hop {hop_num}: *Timeout*")
                    elif "ms" in line:
                        parts = [part for part in line.split() if part]
                        if len(parts) >= 4:
                            hop_num = parts[0]
                            ip = parts[-1]
                            
                            # Get only the first valid time for faster display
                            time_value = None
                            for part in parts[1:-1]:
                                if "ms" in part:
                                    try:
                                        time_str = part.replace("ms", "").strip()
                                        if time_str:
                                            time_value = int(time_str)
                                            break
                                    except ValueError:
                                        continue
                            
                            if time_value is not None:
                                formatted_lines.append(f"Hop {hop_num}: {ip} - {time_value}ms")
                            else:
                                formatted_lines.append(f"Hop {hop_num}: {ip} - *Timeout*")
        else:
            for line in lines:
                line = line.strip()
                if line:
                    if "traceroute to" in line:
                        formatted_lines.append(line)
                    else:
                        parts = [part for part in line.split() if part]
                        if len(parts) >= 4:
                            hop_num = parts[0]
                            ip = parts[1]
                            
                            # Get first non-asterisk time
                            time_value = None
                            for t in parts[2:]:
                                if t != "*":
                                    try:
                                        time_value = float(t)
                                        break
                                    except ValueError:
                                        continue
                            
                            if time_value is not None:
                                formatted_lines.append(f"Hop {hop_num}: {ip} - {time_value:.1f}ms")
                            else:
                                formatted_lines.append(f"Hop {hop_num}: {ip} - *Timeout*")

        return "\n".join(formatted_lines)

    def closeEvent(self, event):
        # Track application close
        self.history.add_action('application_close', {
            'window_title': self.windowTitle(),
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkTroubleshooter()
    window.show()
    sys.exit(app.exec())




