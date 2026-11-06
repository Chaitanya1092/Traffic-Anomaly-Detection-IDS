import time
from scapy.all import conf
from detectors.base import BaseDetector

class ARPSpoofDetector(BaseDetector):
    def __init__(self, config_manager, db_manager, logger):
        super().__init__(config_manager, db_manager, logger)
        # Attempt to get system default gateway IP
        self.gateway_ip = self._get_default_gateway()
        self.logger.info(f"ARP Spoof Detector initialized. Target Gateway IP: {self.gateway_ip or 'Undetected'}")
        
        # Keep track of active gateway MAC from packets
        self.gateway_mac = None
        self.last_alert_time = {}

    def _get_default_gateway(self):
        """Use Scapy configurations to retrieve the default gateway IP address."""
        try:
            # conf.route.route("0.0.0.0") returns (interface, ip, gateway)
            routes = conf.route.route("0.0.0.0")
            if routes and len(routes) > 2:
                return routes[2]
        except Exception as e:
            self.logger.error(f"Failed to auto-detect default gateway: {e}")
        return None

    def analyze(self, packet_info):
        # We look closely at ARP packets (especially replies/is-at) and standard IP traffic
        is_arp_reply = packet_info.get("is_arp") and packet_info.get("arp_op") == 2
        
        # Extract IP and MAC mapping to verify
        if is_arp_reply:
            ip_to_check = packet_info.get("arp_psrc")
            mac_to_check = packet_info.get("arp_hwsrc")
        else:
            ip_to_check = packet_info.get("src_ip")
            mac_to_check = packet_info.get("src_mac")

        if not ip_to_check or not mac_to_check:
            return []

        # If gateway IP is not detected yet, try to resolve it from route table
        if not self.gateway_ip:
            self.gateway_ip = self._get_default_gateway()

        alerts = []
        now = packet_info["timestamp"]

        # Check against Gateway MAC spoofing
        if ip_to_check == self.gateway_ip:
            if self.gateway_mac is None:
                # First time seeing the gateway, initialize it
                # Check DB first for gateway MAC
                known_devs = self.db.get_devices()
                gw_dev = next((d for d in known_devs if d["ip_address"] == self.gateway_ip), None)
                if gw_dev:
                    self.gateway_mac = gw_dev["mac_address"]
                else:
                    self.gateway_mac = mac_to_check
                    
            if mac_to_check != self.gateway_mac:
                # Gateway MAC changed!
                cooldown_key = f"gw_{ip_to_check}"
                if now - self.last_alert_time.get(cooldown_key, 0) > 60:
                    self.last_alert_time[cooldown_key] = now
                    
                    desc = (
                        f"CRITICAL: Gateway MAC address conflict detected! "
                        f"Gateway {self.gateway_ip} is advertised by MAC {mac_to_check}, "
                        f"but was previously known as {self.gateway_mac}."
                    )
                    
                    self.logger.critical(f"ARP Spoofing Alert: {desc}")
                    
                    alert_id = self.db.add_alert(
                        alert_type="ARP Spoofing",
                        source_ip=ip_to_check,
                        dest_ip="Broadcast",
                        description=desc,
                        severity="Critical"
                    )
                    
                    alerts.append({
                        "id": alert_id,
                        "alert_type": "ARP Spoofing",
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
                        "source_ip": ip_to_check,
                        "dest_ip": "Broadcast",
                        "description": desc,
                        "severity": "Critical"
                    })
                    
                # Update the gateway MAC to the latest seen (or keep the old one depending on trust,
                # let's alert and update to allow normal operation if it was a real change)
                self.gateway_mac = mac_to_check

        # General LAN IP-to-MAC conflict detection
        else:
            # Query known devices to check if this IP was registered with a different MAC
            known_devs = self.db.get_devices()
            conflicting_device = next(
                (d for d in known_devs if d["ip_address"] == ip_to_check and d["mac_address"] != mac_to_check), 
                None
            )
            
            if conflicting_device:
                # To prevent alerts for normal DHCP reassignments, we can verify that the conflicting MAC 
                # is active and claiming the same IP. We'll raise a High severity alert.
                cooldown_key = f"lan_{ip_to_check}"
                if now - self.last_alert_time.get(cooldown_key, 0) > 60:
                    self.last_alert_time[cooldown_key] = now
                    
                    desc = (
                        f"IP Conflict / Possible ARP Spoofing: Host IP {ip_to_check} "
                        f"is claimed by MAC {mac_to_check}, but was registered to MAC {conflicting_device['mac_address']}."
                    )
                    
                    self.logger.warning(desc)
                    
                    alert_id = self.db.add_alert(
                        alert_type="ARP Spoofing",
                        source_ip=ip_to_check,
                        dest_ip="Broadcast",
                        description=desc,
                        severity="High"
                    )
                    
                    alerts.append({
                        "id": alert_id,
                        "alert_type": "ARP Spoofing",
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
                        "source_ip": ip_to_check,
                        "dest_ip": "Broadcast",
                        "description": desc,
                        "severity": "High"
                    })

        return alerts
