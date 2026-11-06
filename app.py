import os
import time
import threading
import logging
import hmac
from flask import Flask, render_template, jsonify, request, Response, redirect, session, url_for

from config import ConfigManager
from database.db_manager import DBManager
from utils.logger import setup_logger
from utils.packet_processor import PacketProcessor
from utils.csv_exporter import export_alerts_to_csv
from notifications.telegram import TelegramNotifier
from detectors import (
    PortScanDetector,
    TrafficSpikeDetector,
    DNSAnomalyDetector,
    ARPSpoofDetector,
    NewDeviceDetector,
    ICMPFloodDetector,
    MLAnomalyDetector
)


app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)
web_password = os.environ.get("IDS_WEB_PASSWORD", "")

config_mgr = ConfigManager()
db_mgr = DBManager()
logger = setup_logger("ids_system", db_manager=db_mgr, level=logging.INFO)
notifier = TelegramNotifier(config_mgr)

capture_status = "Offline"
capture_error = None
captured_packets_count = 0
capture_thread = None
stop_capture_event = threading.Event()

detectors = []
ml_detector = None


@app.before_request
def require_login():
    if request.endpoint in {"login", "static"}:
        return None
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login"))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if not web_password:
        return "Set IDS_WEB_PASSWORD before starting the IDS.", 503
    if session.get("authenticated"):
        return redirect(url_for("index"))
    if request.method == "POST":
        supplied_password = request.form.get("password", "")
        if hmac.compare_digest(supplied_password.encode("utf-8"), web_password.encode("utf-8")):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Incorrect password."), 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


def packet_callback(packet):
    """Callback function executed for every sniffed network packet."""
    global captured_packets_count
    if stop_capture_event.is_set():
        return

    packet_info = PacketProcessor.parse_packet(packet)
    if not packet_info:
        return

    captured_packets_count += 1

    generated_alerts = []
    for detector in detectors:
        try:
            alerts = detector.analyze(packet_info)
            if alerts:
                generated_alerts.extend(alerts)
        except Exception as e:
            logger.error(f"Error running detector {detector.__class__.__name__}: {e}")

    for alert in generated_alerts:
        try:
            notifier.send_alert(alert)
        except Exception as e:
            logger.error(f"Error sending alert notification: {e}")

def run_sniffer():
    """Background sniffer loop running Scapy sniff()."""
    global capture_status, capture_error
    capture_status = "Starting..."
    logger.info("Initializing Packet Capture Engine...")


    iface = config_mgr.get("network_settings", "interface", default="")
    if iface == "":
        iface = None 

    try:
        from scapy.all import sniff
        capture_status = "Active"
        logger.info(f"Packet Capture Engine online (Interface: {iface or 'Auto-Detect'}).")

        while not stop_capture_event.is_set():
            sniff(
                iface=iface,
                prn=packet_callback,
                store=0,
                timeout=2 
            )
            
    except Exception as e:
        capture_status = "Error"
        capture_error = str(e)
        logger.error(f"Packet Capture Engine encountered a critical error: {e}")
        logger.error("Please verify that you are running as Administrator / root, and have Npcap installed.")

def start_capture_engine():
    """Instantiate detectors and start background sniff thread."""
    global capture_thread, detectors, ml_detector, stop_capture_event, captured_packets_count
    
    stop_capture_event.clear()
    captured_packets_count = 0

    
    port_scan = PortScanDetector(config_mgr, db_mgr, logger)
    traffic_spike = TrafficSpikeDetector(config_mgr, db_mgr, logger)
    dns_anomaly = DNSAnomalyDetector(config_mgr, db_mgr, logger)
    arp_spoof = ARPSpoofDetector(config_mgr, db_mgr, logger)
    new_device = NewDeviceDetector(config_mgr, db_mgr, logger)
    icmp_flood = ICMPFloodDetector(config_mgr, db_mgr, logger)
    
    
    ml_detector = MLAnomalyDetector(config_mgr, db_mgr, logger)
    traffic_spike.ml_detector = ml_detector
    
    detectors = [
        new_device,
        arp_spoof,
        port_scan,
        dns_anomaly,
        icmp_flood,
        traffic_spike  
    ]

    capture_thread = threading.Thread(target=run_sniffer, daemon=True)
    capture_thread.start()

    def cleanup_loop():
        while not stop_capture_event.is_set():
            time.sleep(3600)
            try:
                db_mgr.clear_old_data(days=7)
                logger.info("Database auto-cleanup completed. Purged logs/statistics older than 7 days.")
            except Exception as e:
                logger.error(f"Database auto-cleanup failed: {e}")
                
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()



@app.route("/")
def index():
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/alerts")
def alerts():
    return render_template("alerts.html", active_page="alerts")

@app.route("/stats")
def stats():
    return render_template("stats.html", active_page="stats")

@app.route("/devices")
def devices():
    return render_template("devices.html", active_page="devices")

@app.route("/rules")
def rules():

    conf = config_mgr.config

    interfaces = []
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
    except Exception:
        pass
        
    return render_template(
        "rules.html", 
        active_page="rules", 
        config=conf, 
        interfaces=interfaces
    )



@app.route("/api/status", methods=["GET"])
def get_status():
    """Retrieve engine status and aggregated dashboard metric numbers."""
    summary = db_mgr.get_dashboard_summary()
    
    return jsonify({
        "status": capture_status,
        "error": capture_error,
        "captured_packets": captured_packets_count,
        "total_packets": summary["total_packets"] + captured_packets_count,
        "active_devices": summary["active_devices_count"],
        "unresolved_alerts": summary["unresolved_alerts_count"],
        "recent_alerts": summary["recent_alerts"],
        "top_sources": summary["top_sources"],
        "top_destinations": summary["top_destinations"]
    })

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retrieve dynamic network charts data."""
    limit = request.args.get("limit", default=60, type=int)
    stats_rows = db_mgr.get_traffic_stats(limit=limit)
    
    summary = db_mgr.get_dashboard_summary()
    
    timeline = []
    pps = []
    kbps = []
    
    for r in stats_rows:
        ts_str = r["timestamp"]
        if " " in ts_str:
            ts_str = ts_str.split(" ")[1]
        timeline.append(ts_str)
        pps.append(r["packets_per_sec"])
        kbps.append((r["bytes_per_sec"] * 8) / 1024)  
        
    return jsonify({
        "timeline": timeline,
        "pps": pps,
        "kbps": kbps,
        "protocol_shares": summary["protocol_shares"]
    })

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """API returning paginated/filtered security alerts."""
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    resolved = request.args.get("resolved", default=None)
    severity = request.args.get("severity", default=None)
    
    if resolved is not None:
        resolved = True if resolved.lower() == 'true' else False
        
    alerts_list = db_mgr.get_alerts(limit=limit, offset=offset, resolved=resolved, severity=severity)
    return jsonify(alerts_list)

@app.route("/api/alerts/resolve", methods=["POST"])
def resolve_alert():
    """Resolve a specific alert."""
    data = request.json or {}
    alert_id = data.get("id")
    if not alert_id:
        return jsonify({"success": False, "error": "Missing alert ID"}), 400
        
    success = db_mgr.resolve_alert(alert_id)
    return jsonify({"success": success})

@app.route("/api/alerts/resolve_all", methods=["POST"])
def resolve_all_alerts():
    """Resolve all alerts."""
    count = db_mgr.resolve_all_alerts()
    return jsonify({"success": True, "resolved_count": count})

@app.route("/api/alerts/export", methods=["GET"])
def export_alerts():
    """Export all alerts from the database to CSV."""
    
    all_alerts = db_mgr.get_alerts(limit=10000)
    csv_data = export_alerts_to_csv(all_alerts)
    
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=ids_alerts_export.csv"}
    )

@app.route("/api/devices", methods=["GET"])
def get_devices():
    """Retrieve list of devices discovered on the local network."""
    devices_list = db_mgr.get_devices()
    return jsonify(devices_list)

@app.route("/api/devices/update", methods=["POST"])
def update_device():
    """Toggle device whitelist status or update names."""
    data = request.json or {}
    mac = data.get("mac_address")
    if not mac:
        return jsonify({"success": False, "error": "Missing MAC address"}), 400
        
    is_whitelisted = data.get("is_whitelisted")
    label = data.get("device_label")
    
    success = db_mgr.update_device(
        mac_address=mac,
        is_whitelisted=is_whitelisted,
        device_label=label
    )
    
   
    config_mgr.load()
    
    return jsonify({"success": success})

@app.route("/api/rules/update", methods=["POST"])
def update_rules():
    """API endpoint to save threshold settings from rule forms."""
    try:
        data = request.form or request.json or {}
        
      
        if "packets_per_sec_limit" in data:
            config_mgr.set(int(data["packets_per_sec_limit"]), "packet_thresholds", "packets_per_sec_limit")
        if "bandwidth_limit_kbps" in data:
            config_mgr.set(int(data["bandwidth_limit_kbps"]), "packet_thresholds", "bandwidth_limit_kbps")
            
    
        if "max_ports_per_window" in data:
            config_mgr.set(int(data["max_ports_per_window"]), "scan_thresholds", "max_ports_per_window")
        if "scan_window_seconds" in data:
            config_mgr.set(int(data["scan_window_seconds"]), "scan_thresholds", "window_seconds")
            
    
        if "max_dns_queries" in data:
            config_mgr.set(int(data["max_dns_queries"]), "dns_thresholds", "max_queries_per_window")
        if "dns_window_seconds" in data:
            config_mgr.set(int(data["dns_window_seconds"]), "dns_thresholds", "window_seconds")
            
    
        if "max_pings" in data:
            config_mgr.set(int(data["max_pings"]), "icmp_thresholds", "max_pings_per_window")
        if "icmp_window_seconds" in data:
            config_mgr.set(int(data["icmp_window_seconds"]), "icmp_thresholds", "window_seconds")
            
     
        telegram_enabled = True if data.get("telegram_enabled") in ["true", "on", True] else False
        config_mgr.set(telegram_enabled, "notification_settings", "telegram_enabled")
        
        if "telegram_token" in data:
            config_mgr.set(data["telegram_token"].strip(), "notification_settings", "telegram_token")
        if "telegram_chat_id" in data:
            config_mgr.set(data["telegram_chat_id"].strip(), "notification_settings", "telegram_chat_id")
        if "min_severity" in data:
            config_mgr.set(data["min_severity"], "notification_settings", "min_severity")
            
        
        ml_enabled = True if data.get("ml_enabled") in ["true", "on", True] else False
        config_mgr.set(ml_enabled, "ml_settings", "enabled")
        if "ml_contamination" in data:
            config_mgr.set(float(data["ml_contamination"]), "ml_settings", "contamination")
            
       
        if "interface" in data:
            config_mgr.set(data["interface"], "network_settings", "interface")
            
        logger.info("Detection rules and settings updated successfully.")
        
      
        stop_capture_event.set()
        if capture_thread:
            capture_thread.join(timeout=3)
        start_capture_engine()
        
        return jsonify({"success": True, "message": "Settings saved. Capture engine restarted."})
        
    except Exception as e:
        logger.error(f"Failed to update rules: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Retrieve recent detection and engine operation logs."""
    limit = request.args.get("limit", default=50, type=int)
    logs_list = db_mgr.get_detection_logs(limit=limit)
    return jsonify(logs_list)



if __name__ == "__main__":
    if len(web_password) < 16:
        raise SystemExit("Set IDS_WEB_PASSWORD to a password of at least 16 characters before starting.")

    from waitress import serve

    start_capture_engine()

    serve(app, host="127.0.0.1", port=5000)
