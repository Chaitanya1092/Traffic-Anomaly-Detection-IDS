import time
import math
from detectors.base import BaseDetector

class MLAnomalyDetector(BaseDetector):
    """
    Simple statistical anomaly detector using Z-Score profiling.
    Calculates rolling mean and standard deviation of historical traffic rates.
    Triggers an alert if rates exceed a threshold of standard deviations.
    """
    def __init__(self, config_manager, db_manager, logger):
        super().__init__(config_manager, db_manager, logger)
        self.min_samples = 15
        self.z_threshold = 3.0  # Number of standard deviations
        self.last_alert_time = 0
        self.alert_cooldown = 120  # seconds

    def analyze(self, packet_info):
        # Stub for BaseDetector compliance
        return []

    def analyze_stats(self, latest_stat):
        """
        Compare the latest traffic statistic against historical mean and std dev.
        """
        enabled = self.config.get("ml_settings", "enabled", default=True)
        if not enabled:
            return []

        now = time.time()
        
        try:
            # Query last 100 traffic records from DB
            history = self.db.get_traffic_stats(limit=100)
            if len(history) < self.min_samples:
                # Not enough historical baseline data yet
                return []

            # Extract rates
            pps_list = [row["packets_per_sec"] for row in history]
            bps_list = [row["bytes_per_sec"] for row in history]

            # Calculate Means
            mean_pps = sum(pps_list) / len(pps_list)
            mean_bps = sum(bps_list) / len(bps_list)

            # Calculate Standard Deviations
            var_pps = sum((x - mean_pps) ** 2 for x in pps_list) / len(pps_list)
            var_bps = sum((x - mean_bps) ** 2 for x in bps_list) / len(bps_list)
            
            std_pps = math.sqrt(var_pps)
            std_bps = math.sqrt(var_bps)

            # Avoid division by zero for stable networks
            if std_pps < 1.0: std_pps = 1.0
            if std_bps < 100.0: std_bps = 100.0

            # Calculate Z-Scores for current rates
            current_pps = latest_stat["packets_per_sec"]
            current_bps = latest_stat["bytes_per_sec"]

            z_pps = (current_pps - mean_pps) / std_pps
            z_bps = (current_bps - mean_bps) / std_bps

            # Check if current statistics deviate beyond Z-threshold (e.g. 3.0 std devs)
            if z_pps > self.z_threshold or z_bps > self.z_threshold:
                if now - self.last_alert_time > self.alert_cooldown:
                    self.last_alert_time = now
                    
                    desc = (
                        f"Statistical Anomaly Detected: Traffic rate ({current_pps:.1f} pps, Z-Score: {z_pps:.1f}) "
                        f"or bandwidth ({(current_bps/1024):.2f} KB/s, Z-Score: {z_bps:.1f}) "
                        f"deviates significantly from 100-point historical averages "
                        f"(avg: {mean_pps:.1f} pps, {(mean_bps/1024):.2f} KB/s)."
                    )
                    self.logger.warning(desc)
                    
                    alert_id = self.db.add_alert(
                        alert_type="ML Anomaly",  # Keep type same for DB/UI consistency
                        source_ip="Local Network",
                        dest_ip="N/A",
                        description=desc,
                        severity="Medium"
                    )
                    
                    return [{
                        "id": alert_id,
                        "alert_type": "ML Anomaly",
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
                        "source_ip": "Local Network",
                        "dest_ip": "N/A",
                        "description": desc,
                        "severity": "Medium"
                    }]

        except Exception as e:
            self.logger.error(f"Error in Z-Score anomaly detection: {e}")

        return []
