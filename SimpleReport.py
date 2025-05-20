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
