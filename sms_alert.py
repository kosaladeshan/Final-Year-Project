import os
from twilio.rest import Client
from datetime import datetime
import json

def load_config():
    try:
        with open('sms_alert_settings.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"enabled": False, "phone_number": "", "alert_history": []}

def save_config(config):
    with open('sms_alert_settings.json', 'w') as f:
        json.dump(config, f, indent=4)

def send_sms_alert(message):
    config = load_config()
    if not config["enabled"]:
        print("SMS alerts are disabled")
        return False
    
    try:
        # Load credentials from secret.py
        from SMS_gateway.secret import account_sid, auth_token, twilio_number
        
        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=message,
            from_=twilio_number,
            to=config["phone_number"]
        )
        
        # Log the alert
        alert_history = config.get("alert_history", [])
        alert_history.append({
            "timestamp": datetime.now().isoformat(),
            "message": message.body,
            "status": message.status
        })
        config["alert_history"] = alert_history
        save_config(config)
        
        return True
    except ImportError:
        print("Twilio credentials not found. Please configure secret.py")
        return False
    except Exception as e:
        print(f"Failed to send SMS: {str(e)}")
        return False

if __name__ == "__main__":
    # Test the SMS alert system
    send_sms_alert("Test alert from Network Analysis Tool")
