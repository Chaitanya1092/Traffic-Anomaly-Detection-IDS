import os
import sqlite3
import json
from datetime import datetime, timedelta
from contextlib import contextmanager

class DBManager:
    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, "database", "ids.db")
        else:
            self.db_path = db_path
            
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    @contextmanager
    def get_conn(self):
        """Provide a thread-safe database connection context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def init_db(self):
        """Initialize SQLite tables for alerts, stats, devices, and system logs."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            
            # Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    description TEXT,
                    severity TEXT NOT NULL, -- Low, Medium, High, Critical
                    resolved INTEGER DEFAULT 0
                )
            """)
            
            # Traffic Statistics Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    packet_count INTEGER,
                    bytes_count INTEGER,
                    protocol_counts TEXT, -- JSON structure
                    packets_per_sec REAL,
                    bytes_per_sec REAL
                )
            """)
            
            # Known Devices Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS known_devices (
                    mac_address TEXT PRIMARY KEY,
                    ip_address TEXT,
                    hostname TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_whitelisted INTEGER DEFAULT 0,
                    device_label TEXT DEFAULT ''
                )
            """)
            
            # Detection Logs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    log_level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    message TEXT NOT NULL
                )
            """)

    # Alerts Operations
    def add_alert(self, alert_type, source_ip, dest_ip, description, severity):
        """Insert a new alert into the alerts table."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO alerts (alert_type, source_ip, dest_ip, description, severity) VALUES (?, ?, ?, ?, ?)",
                (alert_type, source_ip, dest_ip, description, severity)
            )
            return cursor.lastrowid

    def get_alerts(self, limit=100, offset=0, resolved=None, severity=None):
        """Retrieve alerts with optional filters and sorting."""
        query = "SELECT * FROM alerts"
        params = []
        conditions = []
        
        if resolved is not None:
            conditions.append("resolved = ?")
            params.append(1 if resolved else 0)
        if severity is not None:
            conditions.append("severity = ?")
            params.append(severity)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def resolve_alert(self, alert_id):
        """Mark an alert as resolved."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))
            return cursor.rowcount > 0

    def resolve_all_alerts(self):
        """Mark all alerts as resolved."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET resolved = 1")
            return cursor.rowcount

    # Traffic Statistics Operations
    def add_traffic_stat(self, packet_count, bytes_count, protocol_counts, packets_per_sec, bytes_per_sec):
        """Log a traffic statistics snapshot."""
        protocol_counts_json = json.dumps(protocol_counts)
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO traffic_statistics (packet_count, bytes_count, protocol_counts, packets_per_sec, bytes_per_sec) VALUES (?, ?, ?, ?, ?)",
                (packet_count, bytes_count, protocol_counts_json, packets_per_sec, bytes_per_sec)
            )
            return cursor.lastrowid

    def get_traffic_stats(self, limit=120):
        """Get recent traffic logs. Defaults to last 120 datapoints (2 mins at 1s intervals)."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM traffic_statistics ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = [dict(row) for row in cursor.fetchall()]
            # Deserialize json protocol counts
            for r in rows:
                try:
                    r['protocol_counts'] = json.loads(r['protocol_counts'])
                except (TypeError, json.JSONDecodeError):
                    r['protocol_counts'] = {}
            # Return in chronological order
            rows.reverse()
            return rows

    # Known Devices Operations
    def register_device(self, mac_address, ip_address, hostname=None):
        """Register or update a device discovered on the network."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mac_address, is_whitelisted, device_label FROM known_devices WHERE mac_address = ?", (mac_address,))
            row = cursor.fetchone()
            
            if row:
                # Update IP and last_seen
                cursor.execute(
                    "UPDATE known_devices SET ip_address = ?, hostname = COALESCE(?, hostname), last_seen = ? WHERE mac_address = ?",
                    (ip_address, hostname, now, mac_address)
                )
                return False, dict(row)  # (is_new, device_details)
            else:
                # Insert new device
                cursor.execute(
                    "INSERT INTO known_devices (mac_address, ip_address, hostname, first_seen, last_seen, is_whitelisted, device_label) VALUES (?, ?, ?, ?, ?, 0, '')",
                    (mac_address, ip_address, hostname, now, now)
                )
                return True, {
                    "mac_address": mac_address,
                    "ip_address": ip_address,
                    "hostname": hostname or "",
                    "is_whitelisted": 0,
                    "device_label": ""
                }

    def get_devices(self):
        """Get all registered devices."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM known_devices ORDER BY last_seen DESC")
            return [dict(row) for row in cursor.fetchall()]

    def update_device(self, mac_address, is_whitelisted=None, device_label=None):
        """Update whitelist status or name label for a device."""
        fields = []
        params = []
        if is_whitelisted is not None:
            fields.append("is_whitelisted = ?")
            params.append(1 if is_whitelisted else 0)
        if device_label is not None:
            fields.append("device_label = ?")
            params.append(device_label)
            
        if not fields:
            return False
            
        query = f"UPDATE known_devices SET {', '.join(fields)} WHERE mac_address = ?"
        params.append(mac_address)
        
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.rowcount > 0

    # Detection Logs Operations
    def add_detection_log(self, log_level, component, message):
        """Log a detector or capture engine event."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO detection_logs (log_level, component, message) VALUES (?, ?, ?)",
                (log_level, component, message)
            )
            return cursor.lastrowid

    def get_detection_logs(self, limit=100):
        """Retrieve system logs."""
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM detection_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    # Utility Operations
    def get_dashboard_summary(self):
        """Query aggregates needed for dashboard widgets."""
        summary = {
            "total_packets": 0,
            "active_devices_count": 0,
            "unresolved_alerts_count": 0,
            "recent_alerts": [],
            "top_sources": [],
            "top_destinations": [],
            "protocol_shares": {}
        }
        
        with self.get_conn() as conn:
            cursor = conn.cursor()
            
            # Total Packets
            cursor.execute("SELECT SUM(packet_count) FROM traffic_statistics")
            row = cursor.fetchone()
            summary["total_packets"] = row[0] if row[0] is not None else 0
            
            # Active Devices (seen in last 24 hours)
            one_day_ago = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("SELECT COUNT(*) FROM known_devices WHERE last_seen >= ?", (one_day_ago,))
            summary["active_devices_count"] = cursor.fetchone()[0]
            
            # Unresolved alerts count
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE resolved = 0")
            summary["unresolved_alerts_count"] = cursor.fetchone()[0]
            
            # Recent Alerts (last 5)
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5")
            summary["recent_alerts"] = [dict(r) for r in cursor.fetchall()]
            
            # Top Source IPs (from alerts)
            cursor.execute(
                "SELECT source_ip, COUNT(*) as cnt FROM alerts WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT 5"
            )
            summary["top_sources"] = [dict(r) for r in cursor.fetchall()]
            
            # Top Destination IPs (from alerts)
            cursor.execute(
                "SELECT dest_ip, COUNT(*) as cnt FROM alerts WHERE dest_ip IS NOT NULL AND dest_ip != '' GROUP BY dest_ip ORDER BY cnt DESC LIMIT 5"
            )
            summary["top_destinations"] = [dict(r) for r in cursor.fetchall()]
            
            # Protocol Distribution (aggregate from last 100 stat bins)
            cursor.execute("SELECT protocol_counts FROM traffic_statistics ORDER BY timestamp DESC LIMIT 100")
            rows = cursor.fetchall()
            proto_totals = {}
            for r in rows:
                try:
                    pcounts = json.loads(r[0])
                    for proto, count in pcounts.items():
                        proto_totals[proto] = proto_totals.get(proto, 0) + count
                except Exception:
                    continue
            summary["protocol_shares"] = proto_totals
            
        return summary

    def clear_old_data(self, days=7):
        """Purge data older than X days to limit database size."""
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with self.get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM traffic_statistics WHERE timestamp < ?", (cutoff,))
            cursor.execute("DELETE FROM detection_logs WHERE timestamp < ?", (cutoff,))
            # We don't delete alerts unless they are older than 30 days and resolved
            alert_cutoff = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("DELETE FROM alerts WHERE resolved = 1 AND timestamp < ?", (alert_cutoff,))
            return True
