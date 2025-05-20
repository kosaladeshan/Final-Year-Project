import sys
import os
import json
import datetime
import threading
import re
import time
from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout,
                             QMessageBox)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QPalette

# Import our SMS alert system
try:
    from sms_alert import send_test_alert
    SMS_ALERT_AVAILABLE = True
    print("SMS Alert System loaded successfully")
except ImportError as e:
    SMS_ALERT_AVAILABLE = False
    print(f"SMS Alert System not available: {e}")


class NumberTracker(QWidget):
    def __init__(self):
        super().__init__()
        self.settings_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sms_alert_settings.json')
        self.load_settings()
        self.initUI()

    # We don't need the send_sms_direct method anymore as we're using the sms_alert module

    def initUI(self):
        # Set window title and dimensions
        self.setWindowTitle('SMS Alert Number Tracker')
        self.resize(600, 500)
        self.setFixedSize(600, 500)  # This makes the window non-resizable

        # Set the dark background color
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(40, 40, 40))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        self.setPalette(palette)

        # Create layouts
        main_layout = QVBoxLayout()
        current_layout = QHBoxLayout()
        new_layout = QHBoxLayout()

        # Current Number row
        current_label = QLabel("Current Alert Number")
        current_label.setStyleSheet("color: white; font-size: 16px;")
        self.current_field = QLineEdit()
        self.current_field.setStyleSheet("""
            background-color: #c2ff80;
            color: black;
            border-radius: 10px;
            padding: 8px;
            font-size: 16px;
            /* Make placeholder text dark gray for better visibility */
            QLineEdit::placeholder { color: #555555; }
        """)

        # Set the current number from settings
        if self.settings.get('phone_number'):
            self.current_field.setText(self.settings['phone_number'])

        self.remove_button = QPushButton("Remove")
        self.remove_button.setStyleSheet("background-color: #ff3b30; color: white; border-radius: 10px; padding: 8px; font-size: 16px;")
        self.remove_button.clicked.connect(self.remove_number)

        current_layout.addWidget(current_label)
        current_layout.addWidget(self.current_field)
        current_layout.addWidget(self.remove_button)

        # New Number row
        new_label = QLabel("Enter New Number")
        new_label.setStyleSheet("color: white; font-size: 16px;")
        self.new_field = QLineEdit()
        self.new_field.setPlaceholderText("+94718830879")
        self.new_field.setStyleSheet("""
            background-color: #c2ff80;
            color: black;
            border-radius: 10px;
            padding: 8px;
            font-size: 16px;
            /* Make placeholder text dark gray for better visibility */
            QLineEdit::placeholder { color: #555555; }
        """)
        self.add_button = QPushButton("Add")
        self.add_button.setStyleSheet("background-color: #76d572; color: white; border-radius: 10px; padding: 8px; font-size: 16px;")
        self.add_button.clicked.connect(self.add_number)

        new_layout.addWidget(new_label)
        new_layout.addWidget(self.new_field)
        new_layout.addWidget(self.add_button)

        # Test SMS button
        self.test_sms_button = QPushButton("Test SMS Alert")
        self.test_sms_button.setStyleSheet("background-color: #2196F3; color: white; border-radius: 10px; padding: 8px; font-size: 16px;")
        self.test_sms_button.clicked.connect(self.send_test_sms)

        # Add Test SMS button to a separate row
        test_sms_layout = QHBoxLayout()
        test_sms_layout.addStretch(1)  # Push button to the right
        test_sms_layout.addWidget(self.test_sms_button)

        # Alert History
        history_label = QLabel("Alert History (Last 10)")
        history_label.setStyleSheet("color: white; font-size: 16px;")
        self.history_area = QTextEdit()
        self.history_area.setStyleSheet("background-color: #c2ff80; color: black; border-radius: 10px; padding: 8px; font-size: 16px;")
        self.history_area.setReadOnly(True)

        # Add all components to main layout
        main_layout.addLayout(current_layout)
        main_layout.addLayout(new_layout)
        main_layout.addLayout(test_sms_layout)  # Add the Test SMS button layout
        main_layout.addWidget(history_label)
        main_layout.addWidget(self.history_area)

        self.setLayout(main_layout)

        # Update history display
        self.update_history_display()

    def add_number(self):
        new_number = self.new_field.text()
        if new_number:
            self.current_field.setText(new_number)
            self.settings['phone_number'] = new_number
            self.save_settings()
            self.history_area.append(f"Added: {new_number}")
            self.new_field.clear()

    def remove_number(self):
        current_number = self.current_field.text()
        if current_number:
            self.history_area.append(f"Removed: {current_number}")
            self.current_field.clear()
            self.settings['phone_number'] = ""
            self.save_settings()

    def load_settings(self):
        """Load SMS alert settings from JSON file"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    self.settings = json.load(f)
            else:
                # Create default settings if file doesn't exist
                self.settings = {
                    "enabled": True,
                    "phone_number": "+94718830879",
                    "alert_history": []
                }
                self.save_settings()
        except Exception as e:
            print(f"Error loading SMS alert settings: {e}")
            # Create default settings if there's an error
            self.settings = {
                "enabled": True,
                "phone_number": "+94718830879",
                "alert_history": []
            }

    def save_settings(self):
        """Save SMS alert settings to JSON file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            print(f"Error saving SMS alert settings: {e}")
            QMessageBox.warning(
                self,
                "Settings Error",
                f"Failed to save SMS alert settings: {e}"
            )

    def add_alert_to_history(self, message, phone_number):
        """Add a new alert to the history"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = {
            "timestamp": timestamp,
            "message": message,
            "phone_number": phone_number
        }

        # Add to the beginning of the list (most recent first)
        self.settings['alert_history'].insert(0, alert)

        # Keep only the last 10 alerts
        if len(self.settings['alert_history']) > 10:
            self.settings['alert_history'] = self.settings['alert_history'][:10]

        # Update the history display
        self.update_history_display()

        # Save settings
        self.save_settings()

    def update_history_display(self):
        """Update the history text area with the latest alerts"""
        self.history_area.clear()

        if not self.settings['alert_history']:
            self.history_area.append("No alert history available")
            return

        for alert in self.settings['alert_history']:
            timestamp = alert.get('timestamp', 'Unknown')
            message = alert.get('message', 'Unknown')
            phone = alert.get('phone_number', 'Unknown')

            self.history_area.append(f"[{timestamp}] To: {phone}")

            # Format the message for better display
            if "\n" in message:
                # For multi-line messages (detailed alerts)
                self.history_area.append("Message:")
                for line in message.split("\n"):
                    if line.strip():  # Only add non-empty lines
                        self.history_area.append(f"  {line}")
            else:
                # For single-line messages
                self.history_area.append(f"Message: {message}")

            self.history_area.append("-" * 40)

    def send_test_sms(self):
        """Send a test SMS alert to the current number"""
        # Check if a phone number is set
        current_number = self.current_field.text()
        if not current_number:
            QMessageBox.warning(
                self,
                "No Phone Number",
                "Please add a phone number first before sending a test SMS."
            )
            return

        # Check if SMS alerts are enabled
        if not self.settings.get('enabled', True):
            reply = QMessageBox.question(
                self,
                "SMS Alerts Disabled",
                "SMS alerts are currently disabled. Do you want to enable them and send a test message?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.settings['enabled'] = True
                self.save_settings()
            else:
                return

        # Show sending message
        self.test_sms_button.setEnabled(False)
        self.test_sms_button.setText("Sending...")

        # Run in a separate thread to avoid freezing the UI
        def send_sms_thread():
            try:
                # Check if SMS alert system is available
                if not SMS_ALERT_AVAILABLE:
                    QTimer.singleShot(0, lambda: QMessageBox.critical(
                        self,
                        "SMS Alert System Not Available",
                        "The SMS Alert System is not available. Please check your installation."
                    ))
                    return

                # Send test alert using our SMS alert system
                result = send_test_alert(current_number)

                if result:
                    # Update UI
                    QTimer.singleShot(0, lambda: self.update_history_display())
                    QTimer.singleShot(0, lambda: QMessageBox.information(
                        self,
                        "Test SMS Sent",
                        f"Test SMS alert has been sent successfully to {current_number}."
                    ))
                else:
                    # Show error
                    QTimer.singleShot(0, lambda: QMessageBox.critical(
                        self,
                        "SMS Sending Failed",
                        "Failed to send test SMS alert. Please check your SMS alert system configuration."
                    ))
            except Exception as e:
                # Show error
                error_msg = str(e)
                QTimer.singleShot(0, lambda: QMessageBox.critical(
                    self,
                    "SMS Sending Error",
                    f"Error sending test SMS alert: {error_msg}"
                ))
            finally:
                # Re-enable button
                QTimer.singleShot(0, lambda: self.test_sms_button.setEnabled(True))
                QTimer.singleShot(0, lambda: self.test_sms_button.setText("Test SMS Alert"))

        # Start the thread
        threading.Thread(target=send_sms_thread, daemon=True).start()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NumberTracker()
    window.show()
    sys.exit(app.exec())

