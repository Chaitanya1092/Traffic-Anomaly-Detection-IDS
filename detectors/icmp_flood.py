import time
from detectors.base import BaseDetector

class ICMPFloodDetector(BaseDetector):
    def __init__(self, config_manager, db_manager, logger):
        super().__init__(config_manager, db_manager, logger)
        # Structure: { source_ip: [timestamp, ...] }
        self.history = {}
        # Cooldown: { source_ip: last_alert_time }
        self.alert_cooldowns = {}

    def analyze(self, packet_info):
        # We only care about ICMP packets
        if packet_info["protocol"] != "ICMP":
            return []

        src_ip = packet_info["src_ip"]
        if not src_ip:
            return []

        # Load configurations
        threshold = self.config.get("icmp_thresholds", "max_pings_per_window", default=15)
        window = self.config.get("icmp_thresholds", "window_seconds", default=10)
        cooldown_period = 60  # seconds

        now = packet_info["timestamp"]

        # Clean history and record new ICMP packet
        if src_ip not in self.history:
            self.history[src_ip] = []
            
        # Keep only pings within the sliding window
        self.history[src_ip] = [
            ts for ts in self.history[src_ip] if now - ts <= window
        ]
        
        # Add current ping timestamp
        self.history[src_ip].append(now)

        ping_count = len(self.history[src_ip])

        if ping_count >= threshold:
            # Check cooldown
            last_alert = self.alert_cooldowns.get(src_ip, 0)
            if now - last_alert > cooldown_period:
                self.alert_cooldowns[src_ip] = now
                
                desc = f"Host {src_ip} sent {ping_count} ICMP packets within {window} seconds (potential ping flood)."
                
                # Check whitelist
                whitelist = self.config.get("network_settings", "whitelist", default=[])
                src_mac = packet_info.get("src_mac")
                if src_mac in whitelist or src_ip in whitelist:
                    self.logger.info(f"[WHITELISTED] ICMP flood detected from {src_ip} ({src_mac}) but ignored.")
                    return []

                self.logger.warning(f"ICMP Flood detected: {desc}")
                
                alert_id = self.db.add_alert(
                    alert_type="ICMP Flood",
                    source_ip=src_ip,
                    dest_ip=packet_info["dst_ip"],
                    description=desc,
                    severity="Medium"
                )
                
                return [{
                    "id": alert_id,
                    "alert_type": "ICMP Flood",
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
                    "source_ip": src_ip,
                    "dest_ip": packet_info["dst_ip"],
                    "description": desc,
                    "severity": "Medium"
                }]

        return []
