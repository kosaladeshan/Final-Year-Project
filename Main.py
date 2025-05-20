import sys
import os
import json
import warnings
import ctypes  # Add this import
import subprocess  # Add this for subprocess.Popen
import importlib.util  # Add this for dynamic imports
from PyQt6.QtWidgets import QMessageBox, QStatusBar, QProgressBar, QApplication  # Add these for UI elements
from PyQt6.QtCore import QTimer  # Add this for timer functionality
import traceback  # Add this for detailed error tracking
import threading  # Add this for threading support
import signal  # Add this for signal handling
import atexit  # Add this for exit handling

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler to catch unhandled exceptions"""
    # Don't handle KeyboardInterrupt
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # Format the error message
    error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))

    # Log the error
    print("Unhandled exception occurred:")
    print(error_msg)

    # Show error dialog to user
    try:
        QMessageBox.critical(
            None,
            "Application Error",
            f"An unexpected error occurred:\n\n{error_msg}\n\n"
            "The application will now close. Please restart it."
        )
    except:
        # If we can't show a dialog, just print to console
        print("Failed to show error dialog")

    # Clean up and exit
    sys.exit(1)

# Set the global exception handler
sys.excepthook = handle_exception

# Suppress Wireshark warning
warnings.filterwarnings("ignore", category=UserWarning)

# Get the absolute path of the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))

# Debug: Print current directory and list files
print(f"Current directory: {current_dir}")
print("\nFiles in directory:")
for file in os.listdir(current_dir):
    print(f"- {file}")

# Import using full path
real_time_packet_filtering_path = os.path.join(current_dir, "Real_time_Packet_Filtering.py")
print(f"\nLooking for file at: {real_time_packet_filtering_path}")

if os.path.exists(real_time_packet_filtering_path):
    print("File found, attempting to import...")
    spec = importlib.util.spec_from_file_location("Real_time_Packet_Filtering", real_time_packet_filtering_path)
    Real_time_Packet_Filtering = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(Real_time_Packet_Filtering)
    PacketAnalyzer = Real_time_Packet_Filtering.PacketAnalyzer
    print("Import successful!")
else:
    print(f"Could not find Real_time_Packet_Filtering.py at {real_time_packet_filtering_path}")
    sys.exit(1)

from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton,
                            QVBoxLayout, QHBoxLayout, QWidget, QLabel,
                            QSizePolicy)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

# Import local modules with dependency checking
def check_report_dependencies():
    try:
        # Check if SimpleReport.py exists
        simple_report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SimpleReport.py')
        if os.path.exists(simple_report_path):
            print(f"SimpleReport.py found at {simple_report_path}")
            return True
        else:
            print(f"SimpleReport.py not found at {simple_report_path}")
            return False
    except Exception as e:
        print(f"Error checking dependencies: {str(e)}")
        return False

try:
    from Monitoring_Dashboard import NetworkMonitorApp
    from Basic_Network_Troubleshoot import NetworkTroubleshooter
    from Network_Device_And_Vulnerability_Scan import MainWindow as NetworkDeviceScan
    from WIFI_Signals_Details import WifiScannerApp

    # Only import SimpleReport if dependencies are available
    if check_report_dependencies():
        from SimpleReport import SimpleReportWindow
        REPORT_AVAILABLE = True
    else:
        REPORT_AVAILABLE = False
        print("Warning: Report functionality not available. Please install reportlab and Pillow.")
except ImportError as e:
    print(f"Error importing modules: {e}")
    print(f"Current directory: {current_dir}")
    print(f"Python path: {sys.path}")
    sys.exit(1)

class MonitoringDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitoring Tool")
        self.setStyleSheet("background-color: black;")

        # Set cleanup flags for windows
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        # Fix window size
        self.setFixedSize(900, 650)

        # Initialize windows to None
        self.monitoring_window = None
        self.network_troubleshoot_window = None
        self.network_device_scan_window = None
        self.wifi_signals_window = None
        self.packet_analyzer_window = None
        self.report_window = None if REPORT_AVAILABLE else None

        # Initialize app.py process reference
        self.app_py_process = None

        # Create status bar
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("background-color: #333; color: white;")
        self.setStatusBar(self.statusBar)

        # Create SMS Alert toggle button for status bar
        self.sms_alert_btn = QPushButton("SMS Alert: ON")
        self.sms_alert_btn.setFont(QFont("Arial", 9))
        self.sms_alert_btn.clicked.connect(self.toggle_sms_alert)
        self.sms_alert_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 3px;
                padding: 3px 8px;
                text-align: center;
                min-height: 20px;
                max-width: 100px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3c8c40;
            }
        """)
        self.sms_alert_btn.setFixedSize(100, 20)

        # Load current SMS alert state
        self.load_sms_alert_state()

        # Add SMS Alert button to status bar (left side)
        self.statusBar.addWidget(self.sms_alert_btn)

        # Create progress bar
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 100)
        self.progressBar.setTextVisible(True)
        self.progressBar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #76797C;
                border-radius: 5px;
                text-align: center;
                color: white;
                background-color: #333;
            }
            QProgressBar::chunk {
                background-color: #05B8CC;
                border-radius: 5px;
            }
        """)
        self.progressBar.setFixedWidth(200)
        self.progressBar.hide()  # Hide initially

        # Add progress bar to status bar (right side)
        self.statusBar.addPermanentWidget(self.progressBar)

        # Initialize window states
        self.window_states = {
            'packet_analyzer': False,
            'network_device_scan': False,
            'wifi_signals': False,
            'network_troubleshoot': False
        }

        # Connect window close events
        self.connect_window_close_events()

        # Create main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)

        # Title
        title_label = QLabel("Main Window")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont("Arial", 48, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #ff6347;")
        main_layout.addWidget(title_label)

        # Monitoring Dashboard button
        dashboard_button = QPushButton("Monitoring Dashboard")
        dashboard_font = QFont("Arial", 32, QFont.Weight.Bold)
        dashboard_button.setFont(dashboard_font)
        dashboard_button.setStyleSheet("""
            QPushButton {
                background-color: #7ED957;
                color: black;
                border-radius: 25px;
                padding: 15px;
                margin: 10px 0px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #8FE968;
            }
            QPushButton:pressed {
                background-color: #6DC946;
            }
        """)
        dashboard_button.clicked.connect(self.open_monitoring_dashboard)
        main_layout.addWidget(dashboard_button)

        # First row of buttons
        first_row = QHBoxLayout()
        first_row.setSpacing(20)

        # Basic Networking Troubleshoot button
        basic_network_btn = self.create_button("Basic Networking\nTroubleshoot")
        basic_network_btn.clicked.connect(self.open_network_troubleshoot)
        first_row.addWidget(basic_network_btn)

        # Network Device And Vulnerability Scan button
        network_device_btn = self.create_button("Network Device And\nVulnerability Scan")
        network_device_btn.clicked.connect(self.open_network_device_scan)
        first_row.addWidget(network_device_btn)

        main_layout.addLayout(first_row)

        # Second row of buttons
        second_row = QHBoxLayout()
        second_row.setSpacing(20)

        # Real Time Packet Filtering button
        real_time_btn = self.create_button("Real Time Packet\nFiltering")
        real_time_btn.clicked.connect(self.open_packet_analyzer)
        second_row.addWidget(real_time_btn)

        # WiFi Signals Details button
        wifi_signals_btn = self.create_button("WiFi Signals Details")
        wifi_signals_btn.clicked.connect(self.open_wifi_signals)
        second_row.addWidget(wifi_signals_btn)

        main_layout.addLayout(second_row)

        # Third row of buttons
        third_row = QHBoxLayout()
        third_row.setSpacing(20)

        # Alert System button
        alert_system_btn = self.create_button("Alert System")
        alert_system_btn.clicked.connect(self.open_alert_system)
        third_row.addWidget(alert_system_btn)

        # Generate Report button
        generate_report_btn = self.create_button("Generate Report")
        generate_report_btn.clicked.connect(self.open_detail_report)
        if not REPORT_AVAILABLE:
            generate_report_btn.setEnabled(False)
            generate_report_btn.setToolTip(
                "Report functionality requires additional packages.\n"
                "Please install: reportlab and pillow"
            )
        third_row.addWidget(generate_report_btn)

        main_layout.addLayout(third_row)



        # Set central widget
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def open_monitoring_dashboard(self):
        """Open the Monitoring Dashboard window"""
        try:
            print("Opening Monitoring Dashboard...")

            # Check if window exists but is hidden
            if self.monitoring_window and not self.monitoring_window.isVisible():
                self.monitoring_window.show()
                self.monitoring_window.raise_()
                return

            # If window doesn't exist or was closed
            if self.monitoring_window is None:
                try:
                    self.monitoring_window = NetworkMonitorApp()
                    self.monitoring_window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
                    self.monitoring_window.show()
                    self.monitoring_window.raise_()
                except Exception as e:
                    print(f"Error creating Monitoring Dashboard: {str(e)}")
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Failed to create Monitoring Dashboard:\n{str(e)}\n\n"
                        "Please try again or restart the application."
                    )
                    self.monitoring_window = None
                    return

        except Exception as e:
            print(f"Error opening Monitoring Dashboard: {str(e)}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Monitoring Dashboard:\n{str(e)}\n\n"
                "Please try again or restart the application."
            )
            # Clean up any partially created window
            if hasattr(self, 'monitoring_window') and self.monitoring_window:
                self.monitoring_window.close()
                self.monitoring_window.deleteLater()
                self.monitoring_window = None

    def open_network_troubleshoot(self):
        """Open the Network Troubleshoot window"""
        try:
            print("Opening Network Troubleshoot...")  # Debug print
            if self.network_troubleshoot_window is None:
                self.network_troubleshoot_window = NetworkTroubleshooter()
            self.network_troubleshoot_window.show()
            print("Network Troubleshoot window created and shown")  # Debug print
        except Exception as e:
            print(f"Error opening Network Troubleshoot: {str(e)}")  # Debug print

    def open_network_device_scan(self):
        """Open the Network Device And Vulnerability Scan window"""
        try:
            print("Opening Network Device Scanner...")  # Debug print
            if self.network_device_scan_window is None:
                self.network_device_scan_window = NetworkDeviceScan()
            self.network_device_scan_window.show()
            print("Network Device Scanner window created and shown")  # Debug print
        except Exception as e:
            print(f"Error opening Network Device Scanner: {str(e)}")  # Debug print

    def open_wifi_signals(self):
        """Open the WiFi Signals Details window"""
        try:
            print("Opening WiFi Signals Details...")  # Debug print
            if self.wifi_signals_window is None:
                self.wifi_signals_window = WifiScannerApp()
            self.wifi_signals_window.show()
            print("WiFi Signals Details window created and shown")  # Debug print
        except Exception as e:
            print(f"Error opening WiFi Signals Details: {str(e)}")  # Debug print

    def open_packet_analyzer(self):
        """Open the Real Time Packet Filtering window"""
        try:
            print("Opening Real Time Packet Filtering...")

            # Check if running with admin privileges
            if not self.is_admin():
                # Re-run the specific script with admin rights
                import ctypes, sys, os
                script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         'Real_time_Packet_Filtering.py')
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    sys.executable,
                    script_path,
                    None,
                    1
                )
                return

            # If already running as admin, create window normally
            if self.packet_analyzer_window is None:
                from Real_time_Packet_Filtering import PacketAnalyzer
                self.packet_analyzer_window = PacketAnalyzer()

            self.packet_analyzer_window.show()
            self.packet_analyzer_window.raise_()

        except Exception as e:
            print(f"Error opening Real Time Packet Filtering: {str(e)}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Real Time Packet Filtering: {str(e)}\nTry running as Administrator"
            )

    def open_detail_report(self):
        """Generate a comprehensive report from all available module data"""
        try:
            print("Opening Detail Report...")  # Debug print

            # Check if any modules have been run
            data_dir = 'data_temp'
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)

            # Check for data files
            data_files = [
                'real_time_packet.json',
                'wifi_signals_details.json',
                'network_device_and_vulnerability_scan.json',
                'monitoring_dashboard.json',
                'network_troubleshoot_history.json'
            ]

            available_data = []
            missing_data = []

            for file in data_files:
                file_path = os.path.join(data_dir, file)
                alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file)

                if os.path.exists(file_path) or os.path.exists(alt_path):
                    module_name = file.replace('.json', '').replace('_', ' ').title()
                    available_data.append(module_name)
                else:
                    module_name = file.replace('.json', '').replace('_', ' ').title()
                    missing_data.append(module_name)

            if not available_data:
                QMessageBox.warning(
                    self,
                    "No Data Available",
                    "Please run at least one analysis module first.\n\n"
                    "No data files found in the data_temp directory."
                )
                return

            # Generate PDF report automatically without any prompts
            try:
                from Report import SaveInterface
                report_generator = SaveInterface()

                # Show progress in the status bar
                self.statusBar.showMessage("Generating PDF report from existing data...")
                self.progressBar.setValue(0)
                self.progressBar.show()
                QApplication.processEvents()  # Force UI update

                # Define progress callback function
                def update_progress(value):
                    self.progressBar.setValue(value)
                    QApplication.processEvents()  # Force UI update

                # Generate the report silently with progress updates
                result = report_generator.generateSilentReport(external_progress_callback=update_progress)

                # Hide progress bar after a short delay
                QTimer.singleShot(2000, self.progressBar.hide)
                QTimer.singleShot(2000, lambda: self.statusBar.clearMessage())

                if result:
                    QMessageBox.information(
                        self,
                        "Report Generated",
                        "PDF report has been generated successfully and saved to the root folder."
                    )
                else:
                    QMessageBox.warning(
                        self,
                        "Report Generation Failed",
                        "Failed to generate the PDF report. Please check the console for errors."
                    )
            except Exception as e:
                print(f"Error generating silent report: {str(e)}")
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to generate silent report: {str(e)}\n\n"
                    "Please make sure Report.py exists and all required packages are installed."
                )

        except Exception as e:
            print(f"Error opening Detail Report: {str(e)}")  # Debug print
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Detail Report:\n{str(e)}\n\n"
                "Please make sure Report.py exists and all required packages are installed."
            )

    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def create_button(self, text):
        """Helper function to create styled buttons"""
        button = QPushButton(text)
        button_font = QFont("Arial", 18, QFont.Weight.Bold)
        button.setFont(button_font)

        # Default style for all buttons
        base_style = """
            QPushButton {
                background-color: #FFA500;
                color: black;
                border-radius: 20px;
                padding: 15px;
                text-align: center;
                min-height: 80px;
            }
            QPushButton:hover {
                background-color: #FFB52E;
            }
            QPushButton:pressed {
                background-color: #E69500;
            }
        """

        # Special padding for Monitoring Dashboard button
        if text == "Monitoring Dashboard":
            button.setStyleSheet(base_style.replace("padding: 15px;", "padding: 35px;"))
        else:
            button.setStyleSheet(base_style)

        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        return button

    # Removed connect_report_signals method as we're now using file-based data loading

    # Removed generate_module_report method as we're now using a centralized report approach

    def install_report_dependencies(self):
        """Install required packages for reporting"""
        try:
            # Check if SimpleReport.py exists
            simple_report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SimpleReport.py')
            if os.path.exists(simple_report_path):
                print(f"SimpleReport.py found at {simple_report_path}")
                return True

            # If SimpleReport.py doesn't exist, create it
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Icon.Question)
            msg.setText("SimpleReport.py is missing. Would you like to create it?")
            msg.setWindowTitle("Create SimpleReport")
            msg.setStandardButtons(
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No
            )

            if msg.exec() == QMessageBox.StandardButton.Yes:
                print("Creating SimpleReport.py...")
                # Create SimpleReport.py
                with open(simple_report_path, 'w') as f:
                    f.write('''
import sys
import socket
import psutil
import datetime
import json
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QPushButton, QLabel, QTextEdit, QFileDialog,
                            QMessageBox, QProgressDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread

class SimpleReportWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Simple Report Generator")
        self.setGeometry(100, 100, 800, 600)

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create text area
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        main_layout.addWidget(self.text_area)

        # Create buttons
        button_layout = QHBoxLayout()

        self.save_btn = QPushButton("Save as PDF")
        self.save_btn.clicked.connect(self.save_as_pdf)
        button_layout.addWidget(self.save_btn)

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)

        main_layout.addLayout(button_layout)

        # Load data
        self.load_data()

    def load_data(self):
        try:
            # Check for data files
            data_dir = 'data_temp'
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)

            # Check for data files
            data_files = [
                'real_time_packet.json',
                'wifi_signals_details.json',
                'network_device_and_vulnerability_scan.json',
                'monitoring_dashboard.json',
                'network_troubleshoot_history.json'
            ]

            available_data = []

            for file in data_files:
                file_path = os.path.join(data_dir, file)
                alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file)

                if os.path.exists(file_path) or os.path.exists(alt_path):
                    module_name = file.replace('.json', '').replace('_', ' ').title()
                    available_data.append(module_name)

            # Display available data
            report_text = "Simple Report Generator\n"
            report_text += "======================\n\n"
            report_text += f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

            report_text += "Available Data Sources:\n"
            report_text += "----------------------\n"
            for data_source in available_data:
                report_text += f"- {data_source}\n"

            self.text_area.setText(report_text)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load data: {str(e)}")

    def save_as_pdf(self):
        QMessageBox.information(self, "Info", "PDF generation not implemented in this simple version.")

def main():
    app = QApplication(sys.argv)
    window = SimpleReportWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
''')

                QMessageBox.information(
                    self,
                    "Success",
                    "SimpleReport.py created successfully.\n"
                    "The application will now restart."
                )
                # Restart the application
                python = sys.executable
                os.execl(python, python, *sys.argv)
                return True
            return False

        except Exception as e:
            error_msg = f"Failed to create SimpleReport.py: {str(e)}"
            print(error_msg)
            QMessageBox.critical(
                self,
                "Error",
                f"{error_msg}\n\n"
                "Please create SimpleReport.py manually."
            )
            return False

    def check_running_applications(self):
        """Check which applications are running and available for reporting"""
        running_apps = []
        missing_apps = []

        # Reset window states based on actual window status
        if hasattr(self, 'packet_analyzer_window') and self.packet_analyzer_window and not self.packet_analyzer_window.isHidden():
            running_apps.append("Packet Analysis")
            self.window_states['packet_analyzer'] = True
        else:
            missing_apps.append("Packet Analysis")
            self.window_states['packet_analyzer'] = False

        if hasattr(self, 'network_device_scan_window') and self.network_device_scan_window and not self.network_device_scan_window.isHidden():
            running_apps.append("Network Device Scan")
            self.window_states['network_device_scan'] = True
        else:
            missing_apps.append("Network Device Scan")
            self.window_states['network_device_scan'] = False

        if hasattr(self, 'wifi_signals_window') and self.wifi_signals_window and not self.wifi_signals_window.isHidden():
            running_apps.append("WiFi Signals")
            self.window_states['wifi_signals'] = True
        else:
            missing_apps.append("WiFi Signals")
            self.window_states['wifi_signals'] = False

        if hasattr(self, 'network_troubleshoot_window') and self.network_troubleshoot_window and not self.network_troubleshoot_window.isHidden():
            running_apps.append("Network Troubleshoot")
            self.window_states['network_troubleshoot'] = True
        else:
            missing_apps.append("Network Troubleshoot")
            self.window_states['network_troubleshoot'] = False

        return running_apps, missing_apps

    def connect_window_close_events(self):
        """Connect close events for all windows to track their states"""
        windows = {
            'packet_analyzer_window': 'packet_analyzer',
            'network_device_scan_window': 'network_device_scan',
            'wifi_signals_window': 'wifi_signals',
            'network_troubleshoot_window': 'network_troubleshoot'
        }

        for window_attr, state_key in windows.items():
            if hasattr(self, window_attr):
                window = getattr(self, window_attr)
                if window:
                    window.closeEvent = lambda event, key=state_key: self.handle_window_close(event, key)

    def handle_window_close(self, event, window_key):
        """Handle window close events and update states"""
        self.window_states[window_key] = False
        event.accept()

    def destroy_window(self, window_name):
        """Safely destroy a window instance"""
        try:
            window = getattr(self, window_name, None)
            if window:
                window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)  # Ensure proper cleanup
                window.close()
                window.deleteLater()  # Schedule for deletion
                setattr(self, window_name, None)
        except Exception as e:
            print(f"Error destroying {window_name}: {str(e)}")

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
            data_dir = 'data_temp'

            # Delete each file if it exists
            for filename in files_to_clean:
                file_path = os.path.join(data_dir, filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_count += 1
                    print(f"Deleted {file_path}")

            # Show confirmation message
            if deleted_count > 0:
                QMessageBox.information(
                    self,
                    "Cleanup Complete",
                    f"Successfully cleaned {deleted_count} temporary data files."
                )
            else:
                QMessageBox.information(
                    self,
                    "Cleanup Complete",
                    "No temporary files found to clean."
                )

        except Exception as e:
            print(f"Error cleaning temp files: {e}")
            QMessageBox.warning(
                self,
                "Cleanup Warning",
                f"Some files could not be deleted: {str(e)}"
            )

    def cleanup(self):
        """Clean up all resources and windows"""
        try:
            # List of all window attributes to clean up
            windows = [
                'monitoring_window',
                'network_troubleshoot_window',
                'network_device_scan_window',
                'wifi_signals_window',
                'packet_analyzer_window',
                'report_window'
            ]

            # Close and clean up each window
            for window_name in windows:
                if hasattr(self, window_name):
                    window = getattr(self, window_name)
                    if window:
                        try:
                            window.close()
                            window.deleteLater()
                            setattr(self, window_name, None)
                        except Exception as e:
                            print(f"Error cleaning up {window_name}: {str(e)}")

            # Terminate app.py process if it's running
            if hasattr(self, 'app_py_process') and self.app_py_process:
                try:
                    if self.app_py_process.poll() is None:  # Process is still running
                        print("Terminating app.py process...")
                        self.app_py_process.terminate()
                        # Give it a moment to terminate gracefully
                        import time
                        time.sleep(0.5)
                        # Force kill if still running
                        if self.app_py_process.poll() is None:
                            self.app_py_process.kill()
                        print("app.py process terminated")
                    self.app_py_process = None
                except Exception as e:
                    print(f"Error terminating app.py process: {str(e)}")

            # Reset window states
            self.window_states = {
                'packet_analyzer': False,
                'network_device_scan': False,
                'wifi_signals': False,
                'network_troubleshoot': False
            }

        except Exception as e:
            print(f"Error during cleanup: {str(e)}")

    def closeEvent(self, event):
        """Handle window closing"""
        try:
            # Ask user if they want to clean temporary files
            reply = QMessageBox.question(
                self,
                "Clean Temporary Files",
                "Do you want to clean temporary data files before closing?\n\n"
                "This will remove all saved data from your analysis sessions.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.clean_temp_files()

            # Explicitly terminate app.py process if it exists
            if hasattr(self, 'app_py_process') and self.app_py_process:
                try:
                    if self.app_py_process.poll() is None:  # Process is still running
                        print("Terminating app.py process from closeEvent...")
                        self.app_py_process.terminate()
                        # Give it a moment to terminate gracefully
                        import time
                        time.sleep(0.5)
                        # Force kill if still running
                        if self.app_py_process.poll() is None:
                            print("Force killing app.py process...")
                            self.app_py_process.kill()
                        print("app.py process terminated successfully")
                    self.app_py_process = None
                except Exception as e:
                    print(f"Error terminating app.py process: {str(e)}")

            # Run general cleanup
            self.cleanup()
            event.accept()
        except Exception as e:
            print(f"Error during window closing: {str(e)}")
            event.accept()

    def open_alert_system(self):
        """Open the Alert System window"""
        try:
            if not hasattr(self, 'alert_system_window') or self.alert_system_window is None:
                from change_number import NumberTracker
                self.alert_system_window = NumberTracker()
                self.alert_system_window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

            self.alert_system_window.show()
            self.alert_system_window.raise_()

        except Exception as e:
            print(f"Error opening Alert System: {str(e)}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Alert System:\n{str(e)}\n\n"
                "Please try again or restart the application."
            )

    def load_sms_alert_state(self):
        """Load the current SMS alert state from settings file"""
        try:
            settings_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sms_alert_settings.json')
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)

                # Update button text and style based on current state
                if settings.get('enabled', True):
                    self.sms_alert_btn.setText("SMS Alert: ON")
                    self.sms_alert_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #4CAF50;
                            color: white;
                            border-radius: 3px;
                            padding: 3px 8px;
                            text-align: center;
                            min-height: 20px;
                            max-width: 100px;
                        }
                        QPushButton:hover {
                            background-color: #45a049;
                        }
                        QPushButton:pressed {
                            background-color: #3c8c40;
                        }
                    """)
                else:
                    self.sms_alert_btn.setText("SMS Alert: OFF")
                    self.sms_alert_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #f44336;
                            color: white;
                            border-radius: 3px;
                            padding: 3px 8px;
                            text-align: center;
                            min-height: 20px;
                            max-width: 100px;
                        }
                        QPushButton:hover {
                            background-color: #d32f2f;
                        }
                        QPushButton:pressed {
                            background-color: #b71c1c;
                        }
                    """)
            else:
                # Create default settings if file doesn't exist
                with open(settings_file, 'w') as f:
                    json.dump({"enabled": True, "phone_number": "+94718830879", "alert_history": []}, f, indent=4)
                self.sms_alert_btn.setText("SMS Alert: ON")
        except Exception as e:
            print(f"Error loading SMS alert state: {e}")

    def toggle_sms_alert(self):
        """Toggle SMS alert system on/off"""
        try:
            settings_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sms_alert_settings.json')
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)

                # Toggle the enabled state
                settings['enabled'] = not settings.get('enabled', True)

                # Save the updated settings
                with open(settings_file, 'w') as f:
                    json.dump(settings, f, indent=4)

                # Update button text and style
                if settings['enabled']:
                    self.sms_alert_btn.setText("SMS Alert: ON")
                    self.sms_alert_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #4CAF50;
                            color: white;
                            border-radius: 3px;
                            padding: 3px 8px;
                            text-align: center;
                            min-height: 20px;
                            max-width: 100px;
                        }
                        QPushButton:hover {
                            background-color: #45a049;
                        }
                        QPushButton:pressed {
                            background-color: #3c8c40;
                        }
                    """)

                    # Show confirmation message
                    QMessageBox.information(
                        self,
                        "SMS Alert Enabled",
                        "SMS Alert system has been enabled. You will receive SMS alerts when anomalies are detected."
                    )

                    # Log the change
                    print("\n" + "=" * 60)
                    print("SMS ALERT SYSTEM ENABLED")
                    print("SMS alerts will be sent when anomalies are detected")
                    print("=" * 60 + "\n")
                else:
                    self.sms_alert_btn.setText("SMS Alert: OFF")
                    self.sms_alert_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #f44336;
                            color: white;
                            border-radius: 3px;
                            padding: 3px 8px;
                            text-align: center;
                            min-height: 20px;
                            max-width: 100px;
                        }
                        QPushButton:hover {
                            background-color: #d32f2f;
                        }
                        QPushButton:pressed {
                            background-color: #b71c1c;
                        }
                    """)

                    # Show confirmation message
                    QMessageBox.information(
                        self,
                        "SMS Alert Disabled",
                        "SMS Alert system has been disabled. You will not receive SMS alerts."
                    )

                    # Log the change
                    print("\n" + "=" * 60)
                    print("SMS ALERT SYSTEM DISABLED")
                    print("No SMS alerts will be sent")
                    print("=" * 60 + "\n")
            else:
                # Create default settings if file doesn't exist
                with open(settings_file, 'w') as f:
                    json.dump({"enabled": True, "phone_number": "+94718830879", "alert_history": []}, f, indent=4)
                self.sms_alert_btn.setText("SMS Alert: ON")

                # Show confirmation message
                QMessageBox.information(
                    self,
                    "SMS Alert Enabled",
                    "SMS Alert system has been enabled. You will receive SMS alerts when anomalies are detected."
                )

                # Log the change
                print("\n" + "=" * 60)
                print("SMS ALERT SYSTEM INITIALIZED AND ENABLED")
                print("SMS alerts will be sent when anomalies are detected")
                print("=" * 60 + "\n")
        except Exception as e:
            print(f"Error toggling SMS alert: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to toggle SMS alert system:\n{str(e)}"
            )

    def toggle_app_py(self):
        """Start or stop app.py process"""
        try:
            # Check if app.py process is already running
            if hasattr(self, 'app_py_process') and self.app_py_process and self.app_py_process.poll() is None:
                # Process is running, kill it
                self.app_py_process.terminate()
                self.app_py_process = None
                QMessageBox.information(
                    self,
                    "app.py Stopped",
                    "The app.py process has been stopped."
                )
            else:
                # Start app.py process
                app_py_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py')
                if os.path.exists(app_py_path):
                    self.app_py_process = subprocess.Popen(
                        [sys.executable, app_py_path],
                        creationflags=subprocess.CREATE_NEW_CONSOLE
                    )
                    QMessageBox.information(
                        self,
                        "app.py Started",
                        "The app.py process has been started in a new window."
                    )
                else:
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Could not find app.py at {app_py_path}"
                    )
        except Exception as e:
            print(f"Error toggling app.py: {str(e)}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to toggle app.py process:\n{str(e)}"
            )

def launch_packet_analyzer():
    try:
        import ctypes, sys, os

        # Check if running as admin
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                'Real_time_Packet_Filtering.py'),
                None,
                1
            )
            return

        # If already admin, launch normally
        packet_analyzer_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          'Real_time_Packet_Filtering.py')
        subprocess.Popen([sys.executable, packet_analyzer_path],
                        creationflags=subprocess.CREATE_NEW_CONSOLE)

    except Exception as e:
        print(f"Error launching Packet Analyzer: {str(e)}")
        QMessageBox.critical(
            None,
            "Error",
            f"Failed to launch Packet Analyzer with admin privileges:\n{str(e)}"
        )

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_app_py():
    """Launch app.py in a separate process and return the process object"""
    try:
        app_py_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py')
        if os.path.exists(app_py_path):
            print(f"Starting app.py from {app_py_path}")
            # Start app.py in a new console window
            process = subprocess.Popen([sys.executable, app_py_path],
                                      creationflags=subprocess.CREATE_NEW_CONSOLE)
            print("app.py started successfully")
            return process
        else:
            print(f"Error: app.py not found at {app_py_path}")
            return None
    except Exception as e:
        print(f"Error launching app.py: {str(e)}")
        return None

# Global variable to store app.py process reference
global_app_py_process = None

# Function to terminate app.py process on exit
def terminate_app_py_on_exit():
    global global_app_py_process
    if global_app_py_process:
        try:
            if global_app_py_process.poll() is None:  # Process is still running
                print("Terminating app.py process on application exit...")
                global_app_py_process.terminate()
                # Give it a moment to terminate gracefully
                import time
                time.sleep(0.5)
                # Force kill if still running
                if global_app_py_process.poll() is None:
                    print("Force killing app.py process...")
                    global_app_py_process.kill()
                print("app.py process terminated successfully on exit")
        except Exception as e:
            print(f"Error terminating app.py process on exit: {str(e)}")

# Signal handler for SIGINT (Ctrl+C) and SIGTERM
def signal_handler(sig, frame):
    print(f"Received signal {sig}, terminating app.py and exiting...")
    terminate_app_py_on_exit()
    sys.exit(0)

if __name__ == "__main__":
    try:
        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Register exit handler
        atexit.register(terminate_app_py_on_exit)

        if not is_admin():
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{os.path.abspath(__file__)}"',
                None,
                1
            )
            sys.exit()

        # Launch app.py in a separate process
        app_py_process = run_app_py()

        # Store in global variable for exit handlers
        global_app_py_process = app_py_process

        # Continue with existing main code
        app = QApplication(sys.argv)
        window = MonitoringDashboard()

        # Store the app.py process reference in the window instance
        if app_py_process:
            window.app_py_process = app_py_process

        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Fatal error during application startup: {str(e)}")
        # Make sure to terminate app.py even on startup error
        terminate_app_py_on_exit()
        sys.exit(1)
