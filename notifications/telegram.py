import requests
import logging

class TelegramNotifier:
    SEVERITY_LEVELS = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3
    }

    SEVERITY_ICONS = {
        "LOW": "🔵",
        "MEDIUM": "🟡",
        "HIGH": "🟠",
        "CRITICAL": "🔴"
    }

    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = logging.getLogger("telegram_notifier")

    def _should_notify(self, severity):
        """Determine if an alert should be sent based on config threshold."""
        enabled = self.config.get("notification_settings", "telegram_enabled", default=False)
        if not enabled:
            return False

        token = self.config.get("notification_settings", "telegram_token", default="")
        chat_id = self.config.get("notification_settings", "telegram_chat_id", default="")
        
        if not token or not chat_id:
            return False

        min_sev_str = self.config.get("notification_settings", "min_severity", default="Medium").upper()
        alert_sev_str = severity.upper()

        min_level = self.SEVERITY_LEVELS.get(min_sev_str, 1)
        alert_level = self.SEVERITY_LEVELS.get(alert_sev_str, 1)

        return alert_level >= min_level

    def send_alert(self, alert):
        """Send a formatted message to the configured Telegram chat."""
        severity = alert.get("severity", "Medium")
        if not self._should_notify(severity):
            return False

        token = self.config.get("notification_settings", "telegram_token")
        chat_id = self.config.get("notification_settings", "telegram_chat_id")

        icon = self.SEVERITY_ICONS.get(severity.upper(), "⚠️")
        alert_type = alert.get("alert_type", "Unknown Anomaly")
        timestamp = alert.get("timestamp", "N/A")
        src_ip = alert.get("source_ip", "N/A")
        dest_ip = alert.get("dest_ip", "N/A")
        desc = alert.get("description", "")

        message = (
            f"{icon} *IDS ALERT: {alert_type}*\n\n"
            f"*Severity:* {severity.upper()}\n"
            f"*Time:* `{timestamp}`\n"
            f"*Source:* `{src_ip}`\n"
            f"*Destination:* `{dest_ip}`\n\n"
            f"*Description:*\n{desc}"
        )

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }

        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                return True
            else:
                self.logger.error(
                    f"Failed to send Telegram alert: HTTP {response.status_code} - {response.text}"
                )
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error when sending Telegram alert: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error when sending Telegram alert: {e}")
            return False
