import time
from detectors.base import BaseDetector

class PortScanDetector(BaseDetector):
    def __init__(self, config_manager, db_manager, logger):
        super().__init__(config_manager, db_manager, logger)
        # Structure: { source_ip: [(timestamp, dst_port), ...] }
        self.history = {}
        # Cooldown to avoid alert spamming: { source_ip: last_alert_time }
        self.alert_cooldowns = {}

    def analyze(self, packet_info):
        # We only care about TCP or UDP ports
        if packet_info["protocol"] not in ["TCP", "UDP"]:
            return []

        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]
        
        if not src_ip or dst_port is None:
            return []

        # Load dynamic configurations
        threshold = self.config.get("scan_thresholds", "max_ports_per_window", default=20)
        window = self.config.get("scan_thresholds", "window_seconds", default=10)
        cooldown_period = 60  # seconds

        now = packet_info["timestamp"]

        # Clean history and record new connection attempt
        if src_ip not in self.history:
            self.history[src_ip] = []
        
        # Keep only attempts within the sliding window
        self.history[src_ip] = [
            (ts, port) for ts, port in self.history[src_ip] if now - ts <= window
        ]
        
        # Add current attempt
        self.history[src_ip].append((now, dst_port))

        # Check unique ports targeted in the window
        unique_ports = {port for _, port in self.history[src_ip]}

        if len(unique_ports) >= threshold:
            # Check cooldown
            last_alert = self.alert_cooldowns.get(src_ip, 0)
            if now - last_alert > cooldown_period:
                self.alert_cooldowns[src_ip] = now
                
                desc = (
                    f"Host {src_ip} attempted connections to {len(unique_ports)} unique ports "
                    f"({list(unique_ports)[:10]}...) within {window} seconds."
                )
                
                # Check whitelist
                whitelist = self.config.get("network_settings", "whitelist", default=[])
                # We want to check MAC if available, or source IP
                src_mac = packet_info.get("src_mac")
                if src_mac in whitelist or src_ip in whitelist:
                    self.logger.info(f"[WHITELISTED] Port scan activity detected from {src_ip} ({src_mac}) but ignored.")
                    return []

                self.logger.warning(f"Port scan detected: {desc}")
                
                alert_id = self.db.add_alert(
                    alert_type="Port Scan",
                    source_ip=src_ip,
                    dest_ip=packet_info["dst_ip"],
                    description=desc,
                    severity="High"
                )
                
                return [{
                    "id": alert_id,
                    "alert_type": "Port Scan",
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
                    "source_ip": src_ip,
                    "dest_ip": packet_info["dst_ip"],
                    "description": desc,
                    "severity": "High"
                }]

        return []
