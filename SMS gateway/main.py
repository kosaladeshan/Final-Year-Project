
import os
import sys
import json
import time
import datetime
import pandas as pd
from typing import Optional
from analyzer import get_analyzer
from smsgateway import send_sms  # Fixed import syntax

def get_sms_settings():
    """Get SMS alert settings from the settings file"""
    try:
        settings_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sms_alert_settings.json')
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
            return settings
        else:
            print(f"Settings file not found: {settings_file}")
            return {"enabled": True, "phone_number": "+94718830879", "alert_history": []}
    except Exception as e:
        print(f"Error loading SMS settings: {e}")
        return {"enabled": True, "phone_number": "+94718830879", "alert_history": []}

def save_sms_settings(settings):
    """Save SMS alert settings to the settings file"""
    try:
        settings_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sms_alert_settings.json')
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving SMS settings: {e}")
        return False

def add_alert_to_history(message, phone_number):
    """Add a new alert to the history"""
    try:
        settings = get_sms_settings()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = {
            "timestamp": timestamp,
            "message": message,
            "phone_number": phone_number
        }

        # Add to the beginning of the list (most recent first)
        settings['alert_history'].insert(0, alert)

        # Keep only the last 10 alerts
        if len(settings['alert_history']) > 10:
            settings['alert_history'] = settings['alert_history'][:10]

        # Save settings
        save_sms_settings(settings)
        return True
    except Exception as e:
        print(f"Error adding alert to history: {e}")
        return False

def get_anomaly_details():
    """
    Get detailed information about the current network metrics
    """
    try:
        # Load the dataset
        csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'combined_network_anomaly_dataset.csv')
        data = pd.read_csv(csv_path, on_bad_lines='skip')

        if data.empty:
            return None

        # Get the latest row
        latest_row = data.iloc[-1]

        # Define thresholds for each metric (low, high)
        thresholds = {
            'latency': (50, 100),  # ms (lower is better)
            'throughput': (500, 800),  # Mbps (higher is better)
            'packet_loss': (2, 5),  # % (lower is better)
            'bandwidth': (500, 800),  # Mbps (higher is better)
            'jitter': (3, 7),  # ms (lower is better)
            'network_speed': (500, 800),  # Mbps (higher is better)
            'error_rate': (1, 3)  # % (lower is better)
        }

        # Check for packet_Loss column (inconsistent naming)
        if 'packet_Loss' in latest_row and 'packet_loss' not in latest_row:
            latest_row['packet_loss'] = latest_row['packet_Loss']

        # Analyze which metrics are problematic
        problematic_metrics = []

        for metric, (low, high) in thresholds.items():
            if metric not in latest_row:
                continue

            value = latest_row[metric]

            # For metrics where higher is better
            if metric in ['throughput', 'bandwidth', 'network_speed']:
                if value < low:
                    severity = "critical"
                elif value < high:
                    severity = "warning"
                else:
                    continue  # Normal value
            # For metrics where lower is better
            else:
                if value > high:
                    severity = "critical"
                elif value > low:
                    severity = "warning"
                else:
                    continue  # Normal value

            problematic_metrics.append({
                'metric': metric,
                'value': value,
                'severity': severity
            })

        # Get anomaly score if available
        anomaly_score = latest_row.get('anomaly_score', None)

        return {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'problematic_metrics': problematic_metrics,
            'anomaly_score': anomaly_score
        }

    except Exception as e:
        print(f"Error getting anomaly details: {str(e)}")
        return None

def monitor_analyzer_and_send_sms(analyzer_func):
    """
    Monitor analyzer results and send SMS if anomaly is detected with detailed information
    """
    try:
        # Get SMS settings
        settings = get_sms_settings()

        # Check if SMS alerts are enabled
        if not settings.get('enabled', True):
            print("SMS alerts are disabled. Skipping.")
            return False

        # Get the phone number
        phone_number = settings.get('phone_number', '')
        if not phone_number:
            print("No phone number configured. Skipping SMS alert.")
            return False

        # Check if an anomaly is detected
        result = analyzer_func()

        if result == 1:  # Anomaly detected
            # Get detailed information about the anomaly
            anomaly_details = get_anomaly_details()

            if anomaly_details:
                # Create a detailed message
                timestamp = anomaly_details['timestamp']
                problematic_metrics = anomaly_details['problematic_metrics']
                anomaly_score = anomaly_details.get('anomaly_score')

                # Start with basic alert message
                message = f"ALERT: Network anomaly detected at {timestamp}!\n"

                # Add anomaly score if available
                if anomaly_score:
                    message += f"Anomaly Score: {anomaly_score:.2f}/10\n"

                # Add problematic metrics details
                if problematic_metrics:
                    message += "Issues detected:\n"
                    for metric in problematic_metrics:
                        name = metric['metric'].replace('_', ' ').title()
                        value = metric['value']
                        severity = metric['severity'].upper()

                        # Format the value based on the metric
                        if name.lower() in ['latency', 'jitter']:
                            formatted_value = f"{value:.2f} ms"
                        elif name.lower() in ['throughput', 'bandwidth', 'network speed']:
                            formatted_value = f"{value:.2f} Mbps"
                        elif name.lower() in ['packet loss', 'error rate']:
                            formatted_value = f"{value:.2f}%"
                        else:
                            formatted_value = f"{value:.2f}"

                        message += f"- {name}: {formatted_value} ({severity})\n"
                else:
                    message += "No specific issues identified, but anomaly detected."
            else:
                # Fallback to basic message if details not available
                message = f"ALERT: Network anomaly detected at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}!"

            print(f"Anomaly detected! Sending detailed SMS to {phone_number}")

            # Try to send SMS using direct method if available
            try:
                # Import the NumberTracker class to use its direct SMS sending method
                sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                from change_number import NumberTracker

                # Create a temporary instance to use the send_sms_direct method
                number_tracker = NumberTracker()
                message_sid = number_tracker.send_sms_direct(message, phone_number)
            except Exception as e:
                print(f"Error using direct SMS method: {str(e)}")
                # Fall back to original method
                message_sid = send_sms(message, phone_number)

            if message_sid:
                print(f"Alert SMS sent successfully! SID: {message_sid}")
                # Add to history
                add_alert_to_history(message, phone_number)
                return True
            else:
                print("Failed to send alert SMS")
                return False
        else:
            print("No anomaly detected. No SMS alert needed.")
            return False

    except Exception as e:
        print(f"Error in monitor_analyzer_and_send_sms: {str(e)}")
        return False

def start_monitoring():
    """Main function to start the monitoring process"""
    analyzer = get_analyzer()

    def get_latest_flag():
        return analyzer.get_latest_anomaly_flag()

    return monitor_analyzer_and_send_sms(analyzer_func=get_latest_flag)

if __name__ == "__main__":
    print("=== Starting Monitoring System ===")
    start_monitoring()
