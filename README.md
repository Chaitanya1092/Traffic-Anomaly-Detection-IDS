# Aegis IDS: Network Traffic Anomaly Detection System

Aegis IDS is a complete, production-style Network Intrusion Detection System (IDS) written in Python. It captures live network packets, performs multiple rule-based and machine-learning-based anomaly detections, logs statistics and alerts to an SQLite database, sends real-time Telegram notifications, and offers a premium dark-mode web dashboard with Chart.js visualization.

---

## Features

### 1. Packet Capture Engine
- Captures live network traffic using **Scapy**.
- Parsed layers: Ethernet, ARP, IP, TCP, UDP, ICMP, and DNS.
- Captures details including MAC addresses, IP addresses, ports, protocol, payload sizes, query details, and timestamps.

### 2. Multi-Vector Detection Engine
- **Port Scan Detection**: Flags hosts contacting many unique ports in a configurable time window.
- **Traffic Spike Detection**: Tracks packets-per-second (pps) and bandwidth (Kbps) in 1s bins; alerts if thresholds are breached.
- **DNS Anomaly Detection**: Alerts on excessive DNS query rates from single hosts.
- **ARP Spoofing Detection**: Automatically identifies default system gateway; alerts on MAC address changes (Critical) or IP conflicts (High).
- **New Device Detection**: Detects and logs previously unseen MAC addresses joining the network.
- **ICMP Flood Detection**: Detects ping flood activity from single source IPs.
- **Machine Learning Anomaly Detection**: Trains an **Isolation Forest** model (from `scikit-learn`) on historical bandwidth and packet rate statistics, raising alerts for structural traffic deviations.

### 3. Sleek Dark-Mode Dashboard (Flask)
- **Dashboard**: Key metric cards, recent alert tables, top alert sources, and protocol shares.
- **Alerts Log**: View, filter by status or severity, resolve alerts, and export data directly to CSV.
- **Traffic Statistics**: Real-time throughput timeline graph (PPS & Kbps) and live operational log viewer.
- **Devices Inventory**: List of all discovered network nodes, whitelisting toggle (bypasses alerts), and friendly labeling.
- **Detection Rules**: Web configurations for all thresholds, network interface selection, and Telegram notifications.

### 4. Real-time Telegram Notifications
- Rich formatting with severity-colored status icons (🔵 Low, 🟡 Medium, 🟠 High, 🔴 Critical).
- Delivers alert details (type, timestamp, offending IP, description, severity) directly to your channel.
- Safe queueing: does not block or crash the packet capture thread during network dropouts.

---

## Project Structure

```
IDS/
├── app.py                   # Main Flask app & capture engine bootstrapper
├── config.py                # Configuration load/save helper class
├── requirements.txt         # Project dependencies
├── README.md                # Setup & operation manual
├── database/
│   ├── __init__.py
│   └── db_manager.py        # Thread-safe SQLite queries and table schema init
├── detectors/
│   ├── __init__.py
│   ├── base.py              # Detector interface class
│   ├── arp_spoof.py         # Gateways MAC & IP conflict checks
│   ├── dns_anomaly.py       # DNS flood checks
│   ├── icmp_flood.py        # ICMP/ping rate checks
│   ├── ml_anomaly.py        # Isolation Forest stats outlier engine
│   ├── new_device.py        # Device inventory discovery
│   ├── port_scan.py         # Port scan thresholds evaluator
│   └── traffic_spike.py     # PPS & Kbps rate evaluator & DB writer
├── notifications/
│   ├── __init__.py
│   └── telegram.py          # Telegram API notifier
├── templates/               # UI layout structures
│   ├── base.html
│   ├── dashboard.html
│   ├── alerts.html
│   ├── stats.html
│   ├── devices.html
│   └── rules.html
├── static/
│   ├── css/
│   │   └── style.css        # Premium dark-mode glassmorphic theme styling
│   └── js/
│       └── dashboard.js     # Chart.js updates & AJAX endpoints controllers
├── logs/
│   └── ids.log              # Rotated structured file logs
└── utils/
    ├── __init__.py
    ├── csv_exporter.py      # Formats alerts data into CSV format
    ├── logger.py            # Structured system logger writing to file & DB
    └── packet_processor.py  # Layered scapy packet metadata parser
```

---

## Installation & Setup

### Prerequisites
1. **Python 3.12+** must be installed.
2. **Administrator/Root Privileges**: Sniffing raw network interface packets requires elevated privileges.
3. **Npcap (Windows)**: You **must** install Npcap to enable Scapy packet capture on Windows:
   - Download and install **Npcap** from [npcap.com](https://npcap.com/).
   - Ensure the option **"Install Npcap in WinPcap API-compatible Mode"** is checked during installation.

### Installation Steps

1. **Clone or navigate** to the project directory:
   ```bash
   cd \IDS
   ```

2. **Create a virtual environment** (recommended) and activate it:
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Application

### 1. Launching the System
Since raw socket capturing is restricted by operating systems, you **must run the application as Administrator** (Windows) or using `sudo` (Linux):

- **Windows**: Open a command prompt or PowerShell window **as Administrator**, activate the virtual environment, and run:
  ```powershell
  python app.py
  ```
- **Linux/macOS**:
  ```bash
  sudo ./venv/bin/python app.py
  ```

### 2. Accessing the Web UI
Once launched, open your web browser and navigate to:
```
http://127.0.0.1:5000
```

The dashboard requires a password. Before starting the app, set `IDS_WEB_PASSWORD` to a unique password of at least 16 characters. On Windows PowerShell, set it in the same Administrator window used to run the app:

```powershell
$env:IDS_WEB_PASSWORD = "replace-with-a-long-random-password"
python app.py
```

### Temporary Public Access from Windows

To share the live dashboard over the internet, install [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) and run this in a separate PowerShell window:

```powershell
cloudflared tunnel --url http://127.0.0.1:5000
```

Open the generated `https://....trycloudflare.com` URL and sign in with the password configured above. Keep both the IDS and tunnel running, and keep the PC powered on. The temporary link changes when the tunnel restarts. The app captures traffic visible to this Windows PC; it does not monitor a cloud host or networks the PC cannot see. Share the access password only with intended viewers.

The web server listens only on localhost; use the tunnel rather than exposing port 5000 directly. Do not remove the login or share the password publicly.

### Public Read-only Sample Demo

For an anonymous project-review link, run the separate demo app using fictional sample data. It does not import the live IDS, read its database, or expose network-capture or settings endpoints:

```powershell
python public_demo.py
```

In another terminal, create a temporary HTTPS link:

```powershell
cloudflared tunnel --url http://127.0.0.1:5001
```

Share the generated `https://....trycloudflare.com` link. The demo has no login, is read-only, and clearly labels its data as fictional. Keep the live capture app on its password-protected port 5000.

---

## Security & Resource Controls

- **Authorized Monitoring**: Ensure you only run this tool on networks that you own or are explicitly authorized to audit.
- **Sliding History Windows**: All rate detectors prune memory buffers periodically to ensure a constant, extremely low memory footprint.
- **Auto-Cleanup**: A background daemon thread automatically runs database cleanups every hour, purging statistics and telemetry older than 7 days, and resolved alerts older than 30 days. This keeps the SQLite database files highly optimized.
