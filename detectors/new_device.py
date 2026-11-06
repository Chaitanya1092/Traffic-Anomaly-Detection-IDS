import time
from detectors.base import BaseDetector

class NewDeviceDetector(BaseDetector):
    def __init__(self, config_manager, db_manager, logger):
        super().__init__(config_manager, db_manager, logger)
        # Fast cache for MAC addresses to reduce DB reads
        self.known_macs = set()
        self._load_known_macs()

    def _load_known_macs(self):
        """Pre-populate the in-memory cache from the SQLite database."""
        try:
            devices = self.db.get_devices()
            for dev in devices:
                self.known_macs.add(dev["mac_address"].lower())
        except Exception as e:
            self.logger.error(f"Failed to load known devices into cache: {e}")

    def analyze(self, packet_info):
        src_mac = packet_info.get("src_mac")
        src_ip = packet_info.get("src_ip")
        
        if not src_mac or not src_ip:
            return []

        src_mac_lower = src_mac.lower()

        # If it's in the cache, we just update the database timestamp periodically
        # (the db_manager's register_device handles IP updates and last_seen updates)
        if src_mac_lower in self.known_macs:
            # Periodically register device to keep IP and last_seen updated in DB
            # We don't want to run a DB write for *every* packet to avoid performance hits.
            # Let's rate limit DB updates for known devices (e.g. write to DB at most once per 60 seconds per device)
            # We can handle this inside the main loop or here. 
            return []

        # It's a new device!
        self.known_macs.add(src_mac_lower)
        alerts = []

        try:
            # Register in DB
            is_new, device_info = self.db.register_device(src_mac, src_ip)
            
            # Since we checked our cache, is_new should be True, but verify
            if is_new:
                desc = f"New device discovered on the network. MAC: {src_mac}, IP: {src_ip}."
                self.logger.info(desc)
                
                alert_id = self.db.add_alert(
                    alert_type="New Device",
                    source_ip=src_ip,
                    dest_ip="N/A",
                    description=desc,
                    severity="Low"
                )
                
                alerts.append({
                    "id": alert_id,
                    "alert_type": "New Device",
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet_info["timestamp"])),
                    "source_ip": src_ip,
                    "dest_ip": "N/A",
                    "description": desc,
                    "severity": "Low"
                })
        except Exception as e:
            self.logger.error(f"Error registering new device {src_mac}: {e}")

        return alerts
