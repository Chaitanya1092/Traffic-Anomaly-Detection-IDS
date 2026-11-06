"""Anonymous, read-only demonstration app backed only by fictional sample data."""

import csv
import io
from datetime import datetime, timedelta

from flask import Flask, Response, jsonify, render_template, request
from waitress import serve


app = Flask(__name__)

ALERTS = [
    {
        "id": 6,
        "alert_type": "Port Scan",
        "severity": "High",
        "source_ip": "192.0.2.25",
        "dest_ip": "198.51.100.10",
        "description": "Demo: repeated connections to 24 unique ports in 10 seconds.",
        "resolved": 0,
        "minutes_ago": 2,
    },
    {
        "id": 5,
        "alert_type": "Traffic Spike",
        "severity": "Medium",
        "source_ip": "192.0.2.42",
        "dest_ip": "198.51.100.20",
        "description": "Demo: traffic reached 235 packets/sec, above the sample threshold.",
        "resolved": 0,
        "minutes_ago": 7,
    },
    {
        "id": 4,
        "alert_type": "DNS Anomaly",
        "severity": "Medium",
        "source_ip": "192.0.2.18",
        "dest_ip": "198.51.100.53",
        "description": "Demo: 48 DNS queries observed within the sample 10-second window.",
        "resolved": 0,
        "minutes_ago": 13,
    },
    {
        "id": 3,
        "alert_type": "New Device",
        "severity": "Low",
        "source_ip": "192.0.2.63",
        "dest_ip": "N/A",
        "description": "Demo: a previously unseen device joined the sample network.",
        "resolved": 1,
        "minutes_ago": 26,
    },
    {
        "id": 2,
        "alert_type": "ARP Spoofing",
        "severity": "Critical",
        "source_ip": "192.0.2.77",
        "dest_ip": "192.0.2.1",
        "description": "Demo: sample gateway IP was advertised by an unexpected device.",
        "resolved": 1,
        "minutes_ago": 41,
    },
    {
        "id": 1,
        "alert_type": "ICMP Flood",
        "severity": "Low",
        "source_ip": "192.0.2.91",
        "dest_ip": "198.51.100.30",
        "description": "Demo: ICMP packet rate briefly exceeded the sample threshold.",
        "resolved": 1,
        "minutes_ago": 58,
    },
]

DEVICES = [
    {
        "device_label": "Demo Workstation",
        "mac_address": "02:00:00:00:00:01",
        "ip_address": "192.0.2.18",
        "hostname": "workstation.demo.invalid",
        "last_seen": "Sample data",
        "is_whitelisted": 0,
    },
    {
        "device_label": "Demo Gateway",
        "mac_address": "02:00:00:00:00:02",
        "ip_address": "192.0.2.1",
        "hostname": "gateway.demo.invalid",
        "last_seen": "Sample data",
        "is_whitelisted": 1,
    },
    {
        "device_label": "Demo Server",
        "mac_address": "02:00:00:00:00:03",
        "ip_address": "198.51.100.10",
        "hostname": "server.demo.invalid",
        "last_seen": "Sample data",
        "is_whitelisted": 0,
    },
    {
        "device_label": "Demo Sensor",
        "mac_address": "02:00:00:00:00:04",
        "ip_address": "192.0.2.42",
        "hostname": "sensor.demo.invalid",
        "last_seen": "Sample data",
        "is_whitelisted": 0,
    },
]

LOGS = [
    {
        "log_level": "INFO",
        "component": "DemoCapture",
        "message": "Sample packet stream initialized.",
        "minutes_ago": 1,
    },
    {
        "log_level": "WARNING",
        "component": "PortScanDetector",
        "message": "Sample port-scan threshold exceeded.",
        "minutes_ago": 2,
    },
    {
        "log_level": "INFO",
        "component": "TrafficSpikeDetector",
        "message": "Sample traffic rate returned below threshold.",
        "minutes_ago": 5,
    },
    {
        "log_level": "INFO",
        "component": "DNSAnomalyDetector",
        "message": "Sample DNS query window evaluated.",
        "minutes_ago": 13,
    },
]


def _timestamp(minutes_ago):
    return (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")


def _alerts():
    return [
        {**alert, "timestamp": _timestamp(alert["minutes_ago"])}
        for alert in ALERTS
    ]


def _page(template, active_page):
    return render_template(
        template,
        active_page=active_page,
        public_demo=True,
        read_only=True,
    )


@app.after_request
def set_demo_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/")
def index():
    return _page("dashboard.html", "dashboard")


@app.route("/alerts")
def alerts():
    return _page("alerts.html", "alerts")


@app.route("/stats")
def stats():
    return _page("stats.html", "stats")


@app.route("/devices")
def devices():
    return _page("devices.html", "devices")


@app.route("/api/status")
def get_status():
    alerts = _alerts()
    unresolved = [alert for alert in alerts if alert["resolved"] == 0]
    return jsonify(
        {
            "status": "Demo",
            "error": None,
            "captured_packets": 248192,
            "total_packets": 248192,
            "active_devices": len(DEVICES),
            "unresolved_alerts": len(unresolved),
            "recent_alerts": alerts[:5],
            "top_sources": [
                {"source_ip": "192.0.2.25", "cnt": 3},
                {"source_ip": "192.0.2.42", "cnt": 2},
                {"source_ip": "192.0.2.18", "cnt": 1},
            ],
            "top_destinations": [
                {"dest_ip": "198.51.100.10", "cnt": 4},
                {"dest_ip": "198.51.100.20", "cnt": 2},
                {"dest_ip": "198.51.100.53", "cnt": 1},
            ],
        }
    )


@app.route("/api/stats")
def get_stats():
    limit = min(max(request.args.get("limit", default=60, type=int), 1), 120)
    samples = []
    now = datetime.now()
    for offset in range(limit - 1, -1, -1):
        samples.append(
            {
                "timestamp": (now - timedelta(seconds=offset)).strftime("%H:%M:%S"),
                "pps": 42 + ((offset * 17 + 11) % 38),
                "kbps": round(180 + ((offset * 29 + 7) % 240) / 10, 1),
            }
        )
    return jsonify(
        {
            "timeline": [sample["timestamp"] for sample in samples],
            "pps": [sample["pps"] for sample in samples],
            "kbps": [sample["kbps"] for sample in samples],
            "protocol_shares": {
                "TCP": 48,
                "UDP": 26,
                "DNS": 12,
                "ICMP": 8,
                "ARP": 6,
            },
        }
    )


@app.route("/api/alerts")
def get_alerts():
    alerts = _alerts()
    resolved = request.args.get("resolved")
    severity = request.args.get("severity")
    if resolved in {"true", "false"}:
        want_resolved = resolved == "true"
        alerts = [alert for alert in alerts if bool(alert["resolved"]) == want_resolved]
    if severity:
        alerts = [alert for alert in alerts if alert["severity"] == severity]

    limit = min(max(request.args.get("limit", default=100, type=int), 1), 100)
    offset = max(request.args.get("offset", default=0, type=int), 0)
    return jsonify(alerts[offset : offset + limit])


@app.route("/api/alerts/export")
def export_alerts():
    output = io.StringIO()
    fields = ("timestamp", "severity", "alert_type", "source_ip", "dest_ip", "description", "resolved")
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for alert in _alerts():
        writer.writerow({field: alert[field] for field in fields})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=aegis_demo_alerts.csv"},
    )


@app.route("/api/devices")
def get_devices():
    return jsonify(DEVICES)


@app.route("/api/logs")
def get_logs():
    logs = [
        {**entry, "timestamp": _timestamp(entry["minutes_ago"])}
        for entry in LOGS
    ]
    limit = min(max(request.args.get("limit", default=50, type=int), 1), 50)
    return jsonify(logs[:limit])


if __name__ == "__main__":
    serve(app, host="127.0.0.1", port=5001)
