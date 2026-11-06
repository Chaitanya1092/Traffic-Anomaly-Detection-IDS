import os
import json
import logging

class ConfigManager:
    DEFAULT_CONFIG = {
        "packet_thresholds": {
            "packets_per_sec_limit": 200,
            "bandwidth_limit_kbps": 2048
        },
        "scan_thresholds": {
            "max_ports_per_window": 20,
            "window_seconds": 10
        },
        "dns_thresholds": {
            "max_queries_per_window": 40,
            "window_seconds": 10
        },
        "icmp_thresholds": {
            "max_pings_per_window": 15,
            "window_seconds": 10
        },
        "ml_settings": {
            "enabled": True,
            "training_interval_minutes": 5,
            "contamination": 0.02
        },
        "notification_settings": {
            "telegram_enabled": False,
            "telegram_token": "",
            "telegram_chat_id": "",
            "min_severity": "Medium"
        },
        "network_settings": {
            "interface": "",
            "whitelist": []
        }
    }

    def __init__(self, config_path=None):
        if config_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.config_path = os.path.join(base_dir, "config", "config.json")
        else:
            self.config_path = config_path
            
        self.config = {}
        self.load()

    def load(self):
        """Load configurations from file or create a default if not found."""
        if not os.path.exists(self.config_path):
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            self.config = self.DEFAULT_CONFIG.copy()
            self.save()
            return

        try:
            with open(self.config_path, "r") as f:
                self.config = json.load(f)
            self._fill_missing_defaults(self.config, self.DEFAULT_CONFIG)
        except Exception as e:
            logging.error(f"Error loading config from {self.config_path}: {e}. Loading defaults.")
            self.config = self.DEFAULT_CONFIG.copy()

    def _fill_missing_defaults(self, current, default):
        """Recursively ensure all default keys exist in loaded config."""
        for key, val in default.items():
            if key not in current:
                current[key] = val
            elif isinstance(val, dict) and isinstance(current[key], dict):
                self._fill_missing_defaults(current[key], val)

    def save(self):
        """Persist configuration dictionary back to disk."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Failed to save config to {self.config_path}: {e}")
            return False

    def get(self, *keys, default=None):
        """Retrieve a nested setting using a variable number of keys."""
        current = self.config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def set(self, value, *keys):
        """Set a nested setting, then automatically save configuration."""
        current = self.config
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
        self.save()
