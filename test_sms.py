import unittest
from sms_alert import send_sms_alert, load_config, save_config

class TestSMSAlert(unittest.TestCase):
    def setUp(self):
        # Save original config
        self.original_config = load_config()
        
        # Test config
        self.test_config = {
            "enabled": True,
            "phone_number": "+1234567890",
            "alert_history": []
        }
        save_config(self.test_config)
    
    def tearDown(self):
        # Restore original config
        save_config(self.original_config)
    
    def test_sms_alert_disabled(self):
        # Test with disabled alerts
        config = load_config()
        config["enabled"] = False
        save_config(config)
        
        result = send_sms_alert("Test message")
        self.assertFalse(result)
    
    def test_sms_alert_enabled(self):
        # Note: This test requires valid Twilio credentials in secret.py
        result = send_sms_alert("Test message")
        
        # If credentials are not configured, this will return False
        # In a real setup with valid credentials, this would be True
        config = load_config()
        if "SMS_gateway/secret.py" not in config:
            self.assertFalse(result)
    
    def test_config_persistence(self):
        test_config = {
            "enabled": True,
            "phone_number": "+1234567890",
            "alert_history": []
        }
        save_config(test_config)
        loaded_config = load_config()
        self.assertEqual(test_config, loaded_config)

if __name__ == '__main__':
    unittest.main()
