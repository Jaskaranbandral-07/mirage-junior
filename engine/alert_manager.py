import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, bot_token=None, chat_id=None):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send_telegram_alert(self, ip, classification, score, summary):
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram config missing. Alert not sent.")
            return False

        emoji = "🔴" if classification == "CRITICAL" else "🟠"
        message = f"""
{emoji} {classification} ALERT — MIRAGE Junior
━━━━━━━━━━━━━━━━━━━━━━━━━━
🌍 IP: {ip}
📊 Threat Score: {score}/100
🎯 Classification: {classification}

📋 Summary:
{summary}
"""
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message
        }
        
        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            logger.info(f"Telegram alert sent for IP {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False
