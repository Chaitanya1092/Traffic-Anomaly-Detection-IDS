import unittest
import os
import json
import time
import shutil
import tempfile
import logging
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR


from config import ConfigManager
from database.db_manager import DBManager
from utils.packet_processor import PacketProcessor
from utils.logger import setup_logger
from utils.csv_exporter import export_alerts_to_csv
from detectors import (
    PortScanDetector,
    TrafficSpikeDetector,
    DNSAnomalyDetector,
    ARPSpoofDetector,
    NewDeviceDetector,
    ICMPFloodDetector,
    MLAnomalyDetector
)
from app import app

class TestNetworkIDS(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_ids.db")
        self.config_path = os.path.join(self.test_dir, "test_config.json")
        self.log_path = os.path.join(self.test_dir, "test_ids.log")

        self.config_mgr = ConfigManager(self.config_path)
        self.db_mgr = DBManager(self.db_path)

        self.logger = setup_logger("test_ids_system", db_manager=self.db_mgr, log_file=self.log_path, level=logging.CRITICAL)

    def tearDown(self):
        logger = logging.getLogger("test_ids_system")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Warning: Cleanup failed for {self.test_dir}: {e}")

    def test_database_initialization(self):
        """Verify that SQLite tables are initialized correctly."""
        with self.db_mgr.get_conn() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]
            
            self.assertIn("alerts", tables)
            self.assertIn("traffic_statistics", tables)
            self.assertIn("known_devices", tables)
            self.assertIn("detection_logs", tables)

    def test_config_defaults_and_updates(self):
        """Verify load, get, and set configuration logic."""

        pps_limit = self.config_mgr.get("packet_thresholds", "packets_per_sec_limit")
        self.assertEqual(pps_limit, 200)


        self.config_mgr.set(350, "packet_thresholds", "packets_per_sec_limit")
        

        new_config_mgr = ConfigManager(self.config_path)
        self.assertEqual(new_config_mgr.get("packet_thresholds", "packets_per_sec_limit"), 350)

    def test_packet_processor(self):
        """Verify Scapy packet parsing to structured dictionary."""
        # 1. Test TCP Packet
        scapy_tcp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")/IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=4321, dport=80)
        parsed_tcp = PacketProcessor.parse_packet(scapy_tcp)
        
        self.assertIsNotNone(parsed_tcp)
        self.assertEqual(parsed_tcp["src_mac"], "00:11:22:33:44:55")
        self.assertEqual(parsed_tcp["dst_mac"], "66:77:88:99:aa:bb")
        self.assertEqual(parsed_tcp["src_ip"], "192.168.1.50")
        self.assertEqual(parsed_tcp["dst_ip"], "192.168.1.1")
        self.assertEqual(parsed_tcp["protocol"], "TCP")
        self.assertEqual(parsed_tcp["src_port"], 4321)
        self.assertEqual(parsed_tcp["dst_port"], 80)

        # 2. Test ARP Packet
        scapy_arp = Ether(src="aa:bb:cc:dd:ee:ff")/ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
        parsed_arp = PacketProcessor.parse_packet(scapy_arp)
        
        self.assertIsNotNone(parsed_arp)
        self.assertTrue(parsed_arp["is_arp"])
        self.assertEqual(parsed_arp["arp_op"], 2)
        self.assertEqual(parsed_arp["src_ip"], "192.168.1.1")
        self.assertEqual(parsed_arp["src_mac"], "aa:bb:cc:dd:ee:ff")

        # 3. Test DNS Query
        scapy_dns = Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53200, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        parsed_dns = PacketProcessor.parse_packet(scapy_dns)
        
        self.assertIsNotNone(parsed_dns)
        self.assertTrue(parsed_dns["is_dns"])
        self.assertEqual(parsed_dns["dns_query"], "google.com")

    def test_detector_new_device(self):
        """Verify new device joins are registered and alert raised."""
        detector = NewDeviceDetector(self.config_mgr, self.db_mgr, self.logger)
        
        pkt = {
            "timestamp": time.time(),
            "size": 64,
            "src_mac": "00:aa:bb:cc:dd:ee",
            "src_ip": "10.0.0.15",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP"
        }
        
        alerts = detector.analyze(pkt)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "New Device")
        self.assertEqual(alerts[0]["severity"], "Low")
        
        alerts_dup = detector.analyze(pkt)
        self.assertEqual(len(alerts_dup), 0)

    def test_detector_port_scan(self):
        """Verify port scan trigger when contacts exceed threshold in window."""
        detector = PortScanDetector(self.config_mgr, self.db_mgr, self.logger)
        self.config_mgr.set(5, "scan_thresholds", "max_ports_per_window") 
        self.config_mgr.set(10, "scan_thresholds", "window_seconds")
        
        now = time.time()
        

        alerts = []
        for port in range(80, 86):
            pkt = {
                "timestamp": now,
                "size": 64,
                "src_ip": "192.168.1.99",
                "dst_ip": "192.168.1.1",
                "dst_port": port,
                "protocol": "TCP"
            }
            alerts.extend(detector.analyze(pkt))

        self.assertTrue(len(alerts) >= 1)
        self.assertEqual(alerts[0]["alert_type"], "Port Scan")
        self.assertEqual(alerts[0]["severity"], "High")

    def test_detector_traffic_spike(self):
        """Verify traffic spike triggers on exceeding PPS and Kbps configurations."""
        detector = TrafficSpikeDetector(self.config_mgr, self.db_mgr, self.logger)
        self.config_mgr.set(10, "packet_thresholds", "packets_per_sec_limit") 
        self.config_mgr.set(100, "packet_thresholds", "bandwidth_limit_kbps")
        
        now = int(time.time())
        

        alerts = []
        for _ in range(12):
            pkt = {
                "timestamp": float(now) + 0.1,
                "size": 1000,
                "src_ip": "192.168.1.5",
                "dst_ip": "192.168.1.1",
                "protocol": "UDP",
                "dst_port": 5000
            }
            alerts.extend(detector.analyze(pkt))
            

        pkt_next_sec = {
            "timestamp": float(now) + 1.1,
            "size": 64,
            "src_ip": "192.168.1.5",
            "dst_ip": "192.168.1.1",
            "protocol": "UDP",
            "dst_port": 5000
        }
        alerts.extend(detector.analyze(pkt_next_sec))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "Traffic Spike")
        self.assertEqual(alerts[0]["severity"], "Medium")

    def test_detector_arp_spoof(self):
        """Verify ARP spoof triggers when gateway MAC address deviates."""
        detector = ARPSpoofDetector(self.config_mgr, self.db_mgr, self.logger)
        detector.gateway_ip = "192.168.1.1"
        detector.gateway_mac = "11:22:33:44:55:66"
        
        pkt = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "src_mac": "ff:ff:ff:ff:ff:ff",
            "dst_ip": "192.168.1.100",
            "protocol": "ARP",
            "is_arp": True,
            "arp_op": 2,
            "arp_psrc": "192.168.1.1",
            "arp_hwsrc": "ff:ff:ff:ff:ff:ff"
        }
        
        alerts = detector.analyze(pkt)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "ARP Spoofing")
        self.assertEqual(alerts[0]["severity"], "Critical")

    def test_ml_anomaly_detector(self):
        """Verify Z-Score anomaly training/baseline evaluation and outlier prediction."""
        detector = MLAnomalyDetector(self.config_mgr, self.db_mgr, self.logger)
        self.config_mgr.set(True, "ml_settings", "enabled")
        

        for i in range(25):
            self.db_mgr.add_traffic_stat(
                packet_count=15,
                bytes_count=750,
                protocol_counts={"TCP": 10, "UDP": 5},
                packets_per_sec=15.0,
                bytes_per_sec=750.0
            )

    
        normal_stat = {"packets_per_sec": 15.0, "bytes_per_sec": 750.0}
        normal_alerts = detector.analyze_stats(normal_stat)
        self.assertEqual(len(normal_alerts), 0)


        outlier_stat = {"packets_per_sec": 100.0, "bytes_per_sec": 50000.0}
        outlier_alerts = detector.analyze_stats(outlier_stat)
        self.assertEqual(len(outlier_alerts), 1)
        self.assertEqual(outlier_alerts[0]["alert_type"], "ML Anomaly")

    def test_flask_endpoints(self):
        """Verify API response structures of Flask server routes."""
        flask_client = app.test_client()
        

        import app as app_module
        original_db = app_module.db_mgr
        app_module.db_mgr = self.db_mgr
        
        try:

            res = flask_client.get("/api/status")
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertIn("status", data)
            self.assertIn("captured_packets", data)
            self.assertIn("unresolved_alerts", data)

            res_dev = flask_client.get("/api/devices")
            self.assertEqual(res_dev.status_code, 200)
            

            res_alerts = flask_client.get("/api/alerts")
            self.assertEqual(res_alerts.status_code, 200)
        finally:

            app_module.db_mgr = original_db

if __name__ == "__main__":
    unittest.main()
