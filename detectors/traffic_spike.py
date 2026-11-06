import time
from detectors.base import BaseDetector

class TrafficSpikeDetector(BaseDetector):
    def __init__(self, config_manager, db_manager, logger):
        super().__init__(config_manager, db_manager, logger)
        # Current bin structure
        self.current_bin_sec = None
        self.packet_count = 0
        self.bytes_count = 0
        self.protocol_counts = {}
        
        # Cooldown to avoid flooding alerts
        self.last_alert_time = 0
        self.alert_cooldown = 30  # seconds

    def analyze(self, packet_info):
        now = packet_info["timestamp"]
        packet_sec = int(now)
        
        alerts = []

        # If it's the first packet, initialize the bin
        if self.current_bin_sec is None:
            self.current_bin_sec = packet_sec
            self.packet_count = 0
            self.bytes_count = 0
            self.protocol_counts = {}

        # If the second has changed, finalize the previous bin
        if packet_sec > self.current_bin_sec:
            alerts = self._finalize_bin()
            # Start new bin
            self.current_bin_sec = packet_sec
            self.packet_count = 0
            self.bytes_count = 0
            self.protocol_counts = {}

        # Accumulate metrics
        self.packet_count += 1
        self.bytes_count += packet_info["size"]
        
        proto = packet_info["protocol"]
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        
        return alerts

    def _finalize_bin(self):
        """Finalize the 1-second bin, save stats, and check thresholds."""
        alerts = []
        if self.packet_count == 0:
            return alerts

        # Calculate rates
        pps = self.packet_count  # since bin size is 1 second
        bps = self.bytes_count
        kbps = (bps * 8) / 1024  # Kilobits per second

        # Save to SQLite database
        try:
            self.db.add_traffic_stat(
                packet_count=self.packet_count,
                bytes_count=self.bytes_count,
                protocol_counts=self.protocol_counts,
                packets_per_sec=float(pps),
                bytes_per_sec=float(bps)
            )
        except Exception as e:
            self.logger.error(f"Error saving traffic stats: {e}")

        # Check configuration limits
        pps_limit = self.config.get("packet_thresholds", "packets_per_sec_limit", default=200)
        bandwidth_limit_kbps = self.config.get("packet_thresholds", "bandwidth_limit_kbps", default=2048)

        now_time = time.time()
        triggered = False
        desc = ""
        severity = "Low"

        if pps > pps_limit:
            triggered = True
            desc += f"Traffic packet rate of {pps} packets/sec exceeded limit of {pps_limit}. "
            severity = "Medium"
            
        if kbps > bandwidth_limit_kbps:
            triggered = True
            desc += f"Bandwidth of {kbps:.2f} Kbps exceeded limit of {bandwidth_limit_kbps} Kbps."
            severity = "High" if severity == "Medium" else "Medium"

        if triggered:
            # Check cooldown
            if now_time - self.last_alert_time > self.alert_cooldown:
                self.last_alert_time = now_time
                self.logger.warning(f"Traffic Spike Detected: {desc}")
                
                alert_id = self.db.add_alert(
                    alert_type="Traffic Spike",
                    source_ip="Network Gateway / Broadcast",
                    dest_ip="Broadcast / Multicast",
                    description=desc,
                    severity=severity
                )
                
                alerts.append({
                    "id": alert_id,
                    "alert_type": "Traffic Spike",
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now_time)),
                    "source_ip": "Network Interface",
                    "dest_ip": "Local Network",
                    "description": desc,
                    "severity": severity
                })

        return alerts
