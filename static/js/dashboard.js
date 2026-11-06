// Dashboard Script - Traffic Anomaly Detection System (Network IDS)

const READ_ONLY_DEMO = document.body.dataset.readOnly === "true";

document.addEventListener("DOMContentLoaded", () => {
    // Determine the current page based on body tag classes or pathname
    const path = window.location.pathname;

    // Start global status polling (runs on all pages for the sidebar status widget)
    initStatusWidget();

    // Route page-specific logic
    if (path === "/" || path.endsWith("/") || path.endsWith("index.html") || path.endsWith("dashboard.html")) {
        initDashboard();
    } else if (path === "/alerts" || path.endsWith("alerts.html")) {
        initAlertsPage();
    } else if (path === "/stats" || path.endsWith("stats.html")) {
        initStatsPage();
    } else if (path === "/devices" || path.endsWith("devices.html")) {
        initDevicesPage();
    } else if (path === "/rules" || path.endsWith("rules.html")) {
        initRulesPage();
    }
});

function apiFetch(url, options) {
    if (document.body.dataset.staticDemo !== "true") {
        return fetch(url, options);
    }

    if (options && options.method && options.method.toUpperCase() !== "GET") {
        return Promise.reject(new Error("The public sample demo is read-only."));
    }

    const requestUrl = new URL(url, window.location.href);
    const files = {
        "/api/status": "status.json",
        "/api/stats": "stats.json",
        "/api/alerts": "alerts.json",
        "/api/logs": "logs.json",
        "/api/devices": "devices.json"
    };
    const file = files[requestUrl.pathname];
    if (!file) {
        return Promise.reject(new Error("This endpoint is unavailable in the public sample demo."));
    }

    const basePath = document.body.dataset.basePath || "./";
    return fetch(`${basePath}demo-data/${file}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Failed to load public sample data (${response.status}).`);
            }
            return response.json();
        })
        .then(data => {
            let result = data;
            if (requestUrl.pathname !== "/api/alerts") {
                if (requestUrl.pathname === "/api/logs") {
                    result = data.slice(0, Math.min(Number(requestUrl.searchParams.get("limit")) || 50, 50));
                } else if (requestUrl.pathname === "/api/stats") {
                    const limit = Math.min(Number(requestUrl.searchParams.get("limit")) || 60, 120);
                    result = {
                        ...data,
                        timeline: data.timeline.slice(-limit),
                        pps: data.pps.slice(-limit),
                        kbps: data.kbps.slice(-limit)
                    };
                }
            } else {
                const severity = requestUrl.searchParams.get("severity");
                const resolved = requestUrl.searchParams.get("resolved");
                const offset = Math.max(Number(requestUrl.searchParams.get("offset")) || 0, 0);
                const limit = Math.min(Number(requestUrl.searchParams.get("limit")) || 100, 100);
                const filtered = data.filter(alert => {
                    const severityMatches = !severity || alert.severity === severity;
                    const resolvedMatches = resolved === null
                        || Boolean(alert.resolved) === (resolved === "true");
                    return severityMatches && resolvedMatches;
                });
                result = filtered.slice(offset, offset + limit);
            }
            return new Response(JSON.stringify(result), {
                headers: { "Content-Type": "application/json" }
            });
        });
}

// --- GLOBAL SYSTEM STATUS WIDGET ---
function initStatusWidget() {
    const statusDot = document.getElementById("status-dot");
    const statusText = document.getElementById("status-text");
    const packetCountSidebar = document.getElementById("sidebar-packets");

    function pollStatus() {
        apiFetch("/api/status")
            .then(res => res.json())
            .then(data => {
                // Update status indicator
                if (data.status === "Active") {
                    statusDot.className = "status-dot active";
                    statusText.textContent = "Monitoring";
                } else if (data.status === "Demo") {
                    statusDot.className = "status-dot active";
                    statusText.textContent = "Sample Data";
                } else if (data.status === "Error") {
                    statusDot.className = "status-dot error";
                    statusText.textContent = "Capture Error";
                } else {
                    statusDot.className = "status-dot";
                    statusText.textContent = data.status || "Offline";
                }

                if (packetCountSidebar) {
                    packetCountSidebar.textContent = data.total_packets.toLocaleString();
                }
            })
            .catch(err => {
                statusDot.className = "status-dot error";
                statusText.textContent = "Disconn.";
                console.error("Failed to connect to backend api:", err);
            });
    }

    pollStatus();
    setInterval(pollStatus, 3000);
}

// --- DASHBOARD PAGE ---
function initDashboard() {
    const cardCaptured = document.getElementById("card-captured");
    const cardDevices = document.getElementById("card-devices");
    const cardAlerts = document.getElementById("card-alerts");
    const alertsBody = document.getElementById("dashboard-alerts-body");
    
    // Chart instances
    let trafficChart = null;
    let protoChart = null;

    // 1. Initialize Charts
    const trafficCtx = document.getElementById("trafficChart")?.getContext("2d");
    if (trafficCtx) {
        trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Packets/s',
                        data: [],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.05)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Bandwidth (Kbps)',
                        data: [],
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.05)',
                        borderWidth: 1.5,
                        tension: 0.3,
                        fill: true,
                        yAxisID: 'y1',
                        borderDash: [5, 5]
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#9ca3af', font: { family: 'Inter' } } }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { color: '#6b7280', maxTicksLimit: 10 }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { color: '#9ca3af' },
                        title: { display: true, text: 'Packets / Sec', color: '#9ca3af' }
                    },
                    y1: {
                        position: 'right',
                        grid: { drawOnChartArea: false },
                        ticks: { color: '#9ca3af' },
                        title: { display: true, text: 'Kbps', color: '#9ca3af' }
                    }
                }
            }
        });
    }

    const protoCtx = document.getElementById("protoChart")?.getContext("2d");
    if (protoCtx) {
        protoChart = new Chart(protoCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#06b6d4', '#0284c7', '#38bdf8', '#10b981', '#f59e0b', '#ef4444', '#6b7280'],
                    borderWidth: 1,
                    borderColor: '#121620'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#9ca3af', boxWidth: 12, font: { family: 'Inter', size: 11 } }
                    }
                },
                cutout: '70%'
            }
        });
    }

    // 2. Poll statistics
    function updateStats() {
        // Main cards
        apiFetch("/api/status")
            .then(res => res.json())
            .then(data => {
                if (cardCaptured) cardCaptured.textContent = data.total_packets.toLocaleString();
                if (cardDevices) cardDevices.textContent = data.active_devices;
                if (cardAlerts) cardAlerts.textContent = data.unresolved_alerts;

                // Render recent alerts table
                if (alertsBody) {
                    if (data.recent_alerts.length === 0) {
                        alertsBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No security alerts detected.</td></tr>`;
                    } else {
                        alertsBody.innerHTML = data.recent_alerts.map(alert => `
                            <tr>
                                <td><span class="badge sev-${alert.severity.toLowerCase()}">${alert.severity}</span></td>
                                <td><strong>${escapeHtml(alert.alert_type)}</strong></td>
                                <td><code>${escapeHtml(alert.source_ip)}</code></td>
                                <td class="text-secondary">${escapeHtml(alert.description)}</td>
                                <td style="white-space: nowrap; color: var(--text-muted);">${alert.timestamp}</td>
                            </tr>
                        `).join('');
                    }
                }
                
                // Top sources and destinations lists
                const topSourcesEl = document.getElementById("top-sources-list");
                if (topSourcesEl) {
                    if (data.top_sources.length === 0) {
                        topSourcesEl.innerHTML = `<li style="text-align: center; color: var(--text-muted); padding: 1rem 0;">No logs yet.</li>`;
                    } else {
                        topSourcesEl.innerHTML = data.top_sources.map(src => `
                            <li class="list-item-flex">
                                <div class="item-meta">
                                    <span class="item-title"><code>${escapeHtml(src.source_ip)}</code></span>
                                    <span class="item-sub">Offending Host</span>
                                </div>
                                <span class="item-stat">${src.cnt} alerts</span>
                            </li>
                        `).join('');
                    }
                }

                const topDestsEl = document.getElementById("top-dests-list");
                if (topDestsEl) {
                    if (data.top_destinations.length === 0) {
                        topDestsEl.innerHTML = `<li style="text-align: center; color: var(--text-muted); padding: 1rem 0;">No logs yet.</li>`;
                    } else {
                        topDestsEl.innerHTML = data.top_destinations.map(dst => `
                            <li class="list-item-flex">
                                <div class="item-meta">
                                    <span class="item-title"><code>${escapeHtml(dst.dest_ip)}</code></span>
                                    <span class="item-sub">Targeted IP</span>
                                </div>
                                <span class="item-stat">${dst.cnt} alerts</span>
                            </li>
                        `).join('');
                    }
                }
            });

        // Graph data
        apiFetch("/api/stats?limit=40")
            .then(res => res.json())
            .then(data => {
                if (trafficChart) {
                    trafficChart.data.labels = data.timeline;
                    trafficChart.data.datasets[0].data = data.pps;
                    trafficChart.data.datasets[1].data = data.kbps;
                    trafficChart.update();
                }

                if (protoChart) {
                    protoChart.data.labels = Object.keys(data.protocol_shares);
                    protoChart.data.datasets[0].data = Object.values(data.protocol_shares);
                    protoChart.update();
                }
            });
    }

    updateStats();
    setInterval(updateStats, 2000);
}

// --- ALERTS PAGE ---
function initAlertsPage() {
    const alertsBody = document.getElementById("alerts-table-body");
    const filterSeverity = document.getElementById("filter-severity");
    const filterStatus = document.getElementById("filter-status");
    const resolveAllBtn = document.getElementById("resolve-all-btn");

    function loadAlerts() {
        let url = "/api/alerts?limit=100";
        
        const sev = filterSeverity.value;
        if (sev) url += `&severity=${sev}`;
        
        const status = filterStatus.value;
        if (status) {
            const resolved = status === "resolved";
            url += `&resolved=${resolved}`;
        }

        apiFetch(url)
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) {
                    alertsBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem 0;">No alerts found matching filters.</td></tr>`;
                    return;
                }

                alertsBody.innerHTML = data.map(alert => {
                    const isResolved = alert.resolved === 1;
                    const actionBtn = READ_ONLY_DEMO
                        ? `<span class="badge">Read only</span>`
                        : isResolved
                        ? `<span class="badge resolved"><i class="fas fa-check"></i> Resolved</span>` 
                        : `<button class="btn btn-outline btn-sm btn-success" onclick="resolveAlert(${alert.id}, this)">Resolve</button>`;
                        
                    return `
                        <tr>
                            <td><span class="badge sev-${alert.severity.toLowerCase()}">${alert.severity}</span></td>
                            <td><strong>${escapeHtml(alert.alert_type)}</strong></td>
                            <td><code>${escapeHtml(alert.source_ip)}</code></td>
                            <td><code>${escapeHtml(alert.dest_ip || 'N/A')}</code></td>
                            <td class="text-secondary">${escapeHtml(alert.description)}</td>
                            <td style="white-space: nowrap; color: var(--text-muted); font-size: 0.85rem;">${alert.timestamp}</td>
                            <td style="text-align: right;">${actionBtn}</td>
                        </tr>
                    `;
                }).join('');
            });
    }

    // Add change listeners
    filterSeverity.addEventListener("change", loadAlerts);
    filterStatus.addEventListener("change", loadAlerts);

    if (resolveAllBtn) {
        resolveAllBtn.addEventListener("click", () => {
            if (confirm("Are you sure you want to mark ALL alerts as resolved?")) {
                fetch("/api/alerts/resolve_all", { method: "POST" })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            loadAlerts();
                        }
                    });
            }
        });
    }

    // Expose resolve method globally for HTML onclick binding
    window.resolveAlert = function(id, btnElement) {
        fetch("/api/alerts/resolve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: id })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                const td = btnElement.parentElement;
                td.innerHTML = `<span class="badge resolved"><i class="fas fa-check"></i> Resolved</span>`;
                // Reload dashboard numbers or statistics if needed
            } else {
                alert("Failed to resolve alert.");
            }
        });
    };

    loadAlerts();
    // Poll alerts list occasionally
    setInterval(loadAlerts, 5000);
}

// --- DETAILED STATISTICS/TRENDS PAGE ---
function initStatsPage() {
    let trafficSpikeChart = null;
    let logsBody = document.getElementById("logs-table-body");

    // 1. Initialize large timeline statistics chart
    const fullTrafficCtx = document.getElementById("fullTrafficChart")?.getContext("2d");
    if (fullTrafficCtx) {
        trafficSpikeChart = new Chart(fullTrafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Bandwidth Usage (Kbps)',
                        data: [],
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.05)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Packets Per Second',
                        data: [],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.05)',
                        borderWidth: 1.5,
                        tension: 0.3,
                        fill: true,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#9ca3af' } }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { color: '#6b7280', maxTicksLimit: 15 }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { color: '#9ca3af' },
                        title: { display: true, text: 'Kilobits / Sec', color: '#9ca3af' }
                    },
                    y1: {
                        position: 'right',
                        grid: { drawOnChartArea: false },
                        ticks: { color: '#9ca3af' },
                        title: { display: true, text: 'Packets / Sec', color: '#9ca3af' }
                    }
                }
            }
        });
    }

    function loadStatsHistory() {
        apiFetch("/api/stats?limit=120")
            .then(res => res.json())
            .then(data => {
                if (trafficSpikeChart) {
                    trafficSpikeChart.data.labels = data.timeline;
                    trafficSpikeChart.data.datasets[0].data = data.kbps;
                    trafficSpikeChart.data.datasets[1].data = data.pps;
                    trafficSpikeChart.update();
                }
            });
    }

    function loadLogs() {
        if (!logsBody) return;
        apiFetch("/api/logs?limit=40")
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) {
                    logsBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No system logs captured yet.</td></tr>`;
                    return;
                }

                logsBody.innerHTML = data.map(log => {
                    let logBadgeClass = "text-secondary";
                    if (log.log_level === "CRITICAL" || log.log_level === "ERROR") logBadgeClass = "text-danger";
                    else if (log.log_level === "WARNING") logBadgeClass = "text-warning";

                    return `
                        <tr>
                            <td><span class="badge ${logBadgeClass.replace('text-', 'sev-')}">${log.log_level}</span></td>
                            <td><code class="text-secondary">${escapeHtml(log.component)}</code></td>
                            <td>${escapeHtml(log.message)}</td>
                            <td style="white-space: nowrap; color: var(--text-muted); font-size: 0.85rem;">${log.timestamp}</td>
                        </tr>
                    `;
                }).join('');
            });
    }

    loadStatsHistory();
    loadLogs();
    
    // Poll stats and logs periodically
    setInterval(loadStatsHistory, 2000);
    setInterval(loadLogs, 4000);
}

// --- DEVICES INVENTORY & WHITELIST ---
function initDevicesPage() {
    const devicesBody = document.getElementById("devices-table-body");

    function loadDevices() {
        apiFetch("/api/devices")
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) {
                    devicesBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem 0;">No devices discovered yet.</td></tr>`;
                    return;
                }

                devicesBody.innerHTML = data.map(device => {
                    const whitelistedChecked = device.is_whitelisted === 1 ? 'checked' : '';
                    const authorizationStatus = READ_ONLY_DEMO
                        ? `<span class="badge">Sample</span>`
                        : `
                            <div style="display: flex; align-items: center; justify-content: space-between;">
                                <label class="switch">
                                    <input type="checkbox" ${whitelistedChecked} onchange="toggleWhitelist('${device.mac_address}', this)">
                                    <span class="slider"></span>
                                </label>
                                <button class="btn btn-outline btn-sm" style="margin-left: 1.5rem;" onclick="renameDevice('${device.mac_address}', '${escapeHtml(device.device_label)}')">
                                    <i class="fas fa-edit"></i> Label
                                </button>
                            </div>
                        `;
                    return `
                        <tr>
                            <td><strong>${escapeHtml(device.device_label || 'Unnamed Device')}</strong></td>
                            <td><code>${escapeHtml(device.mac_address)}</code></td>
                            <td><code>${escapeHtml(device.ip_address)}</code></td>
                            <td class="text-secondary">${escapeHtml(device.hostname || 'Unknown')}</td>
                            <td style="color: var(--text-muted); font-size: 0.85rem;">${device.last_seen}</td>
                            <td>${authorizationStatus}</td>
                        </tr>
                    `;
                }).join('');
            });
    }

    // Toggle Whitelist status
    window.toggleWhitelist = function(mac, checkbox) {
        fetch("/api/devices/update", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                mac_address: mac,
                is_whitelisted: checkbox.checked
            })
        })
        .then(res => res.json())
        .then(data => {
            if (!data.success) {
                alert("Failed to update whitelist status.");
                checkbox.checked = !checkbox.checked; // revert
            }
        })
        .catch(err => {
            console.error(err);
            checkbox.checked = !checkbox.checked; // revert
        });
    };

    // Rename Device
    window.renameDevice = function(mac, currentLabel) {
        const newLabel = prompt("Enter a friendly name label for this device:", currentLabel);
        if (newLabel === null) return; // user cancelled

        fetch("/api/devices/update", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                mac_address: mac,
                device_label: newLabel.trim()
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                loadDevices();
            } else {
                alert("Failed to update label.");
            }
        });
    };

    loadDevices();
}

// --- RULES CONFIGURATION PAGE ---
function initRulesPage() {
    const rulesForm = document.getElementById("rules-config-form");
    const saveStatus = document.getElementById("save-status-indicator");

    if (rulesForm) {
        rulesForm.addEventListener("submit", (e) => {
            e.preventDefault();
            
            // Format form fields
            const formData = new FormData(rulesForm);
            
            // Convert checkboxes to boolean JSON fields
            const jsonBody = {};
            formData.forEach((value, key) => {
                jsonBody[key] = value;
            });
            
            // Handle switches explicitly since browser doesn't send unchecked values
            jsonBody["telegram_enabled"] = document.getElementById("telegram_enabled").checked;
            jsonBody["ml_enabled"] = document.getElementById("ml_enabled").checked;

            if (saveStatus) {
                saveStatus.innerHTML = `<span class="text-secondary"><i class="fas fa-spinner fa-spin"></i> Saving settings...</span>`;
            }

            fetch("/api/rules/update", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(jsonBody)
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    saveStatus.innerHTML = `<span class="badge resolved" style="text-transform:none;"><i class="fas fa-check"></i> ${data.message}</span>`;
                    setTimeout(() => {
                        saveStatus.innerHTML = "";
                    }, 4000);
                } else {
                    saveStatus.innerHTML = `<span class="badge sev-critical" style="text-transform:none;"><i class="fas fa-exclamation-triangle"></i> Error: ${data.error}</span>`;
                }
            })
            .catch(err => {
                saveStatus.innerHTML = `<span class="badge sev-critical" style="text-transform:none;"><i class="fas fa-exclamation-triangle"></i> Communication error.</span>`;
                console.error(err);
            });
        });
    }
}

// --- HTML ESCAPE HELPER ---
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
