from twilio.rest import Client
import logging
from typing import Optional
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def validate_phone_number(phone_number: str) -> bool:
    """Validate phone number format (E.164)"""
    pattern = r'^\+[1-9]\d{1,14}$'
    return bool(re.match(pattern, phone_number))

def send_sms(message_body: str, to_number: str) -> Optional[str]:
    """
    Send SMS using Twilio API
    
    Args:
        message_body (str): The message content to send
        to_number (str): The recipient's phone number in E.164 format
    
    Returns:
        str: The message SID if successful, None if failed
    """
    if not validate_phone_number(to_number):
        logging.error(f"Invalid phone number format: {to_number}")
        return None
        
    if not message_body.strip():
        logging.error("Empty message body")
        return None
        
    try:
        # Load credentials from secret.py
        from .secret import account_sid, auth_token, messaging_service_sid
        
        if not auth_token or len(auth_token) < 32:
            logging.error("Invalid auth token")
            return None
            
        client = Client(account_sid, auth_token)
        
        logging.info(f"Sending SMS to {to_number}")
        message = client.messages.create(
            messaging_service_sid=messaging_service_sid,
            body=message_body,
            to=to_number
        )
        
        logging.info(f"SMS sent successfully. SID: {message.sid}")
        return message.sid
        
    except Exception as e:
        logging.error(f"Error sending SMS: {str(e)}")
        return None

