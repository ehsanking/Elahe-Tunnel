package web

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

const statusTemplateHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elahe Tunnel Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-body: #0f172a;
            --bg-sidebar: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-primary: #3b82f6;
            --accent-success: #10b981;
            --accent-danger: #ef4444;
            --accent-warning: #f59e0b;
            --accent-info: #06b6d4;
            --border-color: #334155;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg-body); color: var(--text-primary); display: flex; min-height: 100vh; }

        /* Sidebar */
        .sidebar { width: 260px; background-color: var(--bg-sidebar); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; padding: 24px; position: fixed; height: 100vh; overflow-y: auto; }
        .logo { font-size: 1.5rem; font-weight: 700; color: var(--text-primary); margin-bottom: 40px; display: flex; align-items: center; gap: 12px; }
        .logo i { color: var(--accent-primary); }
        .nav-item { display: flex; align-items: center; gap: 12px; padding: 12px 16px; color: var(--text-secondary); text-decoration: none; border-radius: 8px; transition: all 0.2s; margin-bottom: 4px; font-weight: 500; }
        .nav-item:hover, .nav-item.active { background-color: rgba(59, 130, 246, 0.1); color: var(--accent-primary); }
        .nav-item i { width: 20px; text-align: center; }

        /* Main Content */
        .main-content { flex: 1; margin-left: 260px; padding: 32px; overflow-y: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
        .page-title { font-size: 1.8rem; font-weight: 600; }
        .status-badge { padding: 6px 16px; border-radius: 9999px; font-size: 0.875rem; font-weight: 500; display: flex; align-items: center; gap: 8px; background-color: rgba(16, 185, 129, 0.1); color: var(--accent-success); border: 1px solid rgba(16, 185, 129, 0.2); }
        .status-badge.disconnected { background-color: rgba(239, 68, 68, 0.1); color: var(--accent-danger); border-color: rgba(239, 68, 68, 0.2); }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background-color: currentColor; }

        /* Grid */
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-bottom: 24px; }
        
        /* Cards */
        .card { background-color: var(--bg-card); border-radius: 16px; padding: 24px; border: 1px solid var(--border-color); box-shadow: var(--shadow-sm); }
        .card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
        .card-title { font-size: 0.875rem; color: var(--text-secondary); font-weight: 500; }
        .card-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.25rem; }
        .card-value { font-size: 1.8rem; font-weight: 700; margin-bottom: 4px; }
        .card-subtext { font-size: 0.875rem; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; }
        .trend-up { color: var(--accent-success); }
        .trend-down { color: var(--accent-danger); }

        /* Chart Container */
        .chart-container { position: relative; height: 300px; width: 100%; }
        .full-width { grid-column: 1 / -1; }

        /* Tables */
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px; color: var(--text-secondary); font-weight: 500; border-bottom: 1px solid var(--border-color); font-size: 0.875rem; }
        td { padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-primary); font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; padding: 16px; }
            .grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <i class="fa-solid fa-bolt"></i>
            <span>Elahe Tunnel</span>
        </div>
        <a href="#" class="nav-item active">
            <i class="fa-solid fa-chart-line"></i>
            <span>Dashboard</span>
        </a>
        <a href="#" class="nav-item">
            <i class="fa-solid fa-network-wired"></i>
            <span>Connections</span>
        </a>
        <a href="#" class="nav-item">
            <i class="fa-solid fa-server"></i>
            <span>Server Status</span>
        </a>
        <a href="#" class="nav-item">
            <i class="fa-solid fa-gear"></i>
            <span>Settings</span>
        </a>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="header">
            <div class="page-title">Dashboard</div>
            <div id="connection-status" class="status-badge">
                <div class="status-dot"></div>
                <span>Connecting...</span>
            </div>
        </div>

        <!-- Stats Grid -->
        <div class="grid">
            <!-- Active Connections -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Active TCP Connections</div>
                    <div class="card-icon" style="background-color: rgba(59, 130, 246, 0.1); color: var(--accent-primary);">
                        <i class="fa-solid fa-link"></i>
                    </div>
                </div>
                <div class="card-value" id="tcp-active">0</div>
                <div class="card-subtext">Current active sessions</div>
            </div>

            <!-- Total Traffic In -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Total Inbound</div>
                    <div class="card-icon" style="background-color: rgba(16, 185, 129, 0.1); color: var(--accent-success);">
                        <i class="fa-solid fa-arrow-down"></i>
                    </div>
                </div>
                <div class="card-value" id="total-in">0 B</div>
                <div class="card-subtext">
                    <span id="rate-in" class="trend-up">0 B/s</span>
                    <span>current rate</span>
                </div>
            </div>

            <!-- Total Traffic Out -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Total Outbound</div>
                    <div class="card-icon" style="background-color: rgba(245, 158, 11, 0.1); color: var(--accent-warning);">
                        <i class="fa-solid fa-arrow-up"></i>
                    </div>
                </div>
                <div class="card-value" id="total-out">0 B</div>
                <div class="card-subtext">
                    <span id="rate-out" class="trend-up">0 B/s</span>
                    <span>current rate</span>
                </div>
            </div>

            <!-- Last Ping -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Last Heartbeat</div>
                    <div class="card-icon" style="background-color: rgba(239, 68, 68, 0.1); color: var(--accent-danger);">
                        <i class="fa-solid fa-heart-pulse"></i>
                    </div>
                </div>
                <div class="card-value" id="last-ping">Never</div>
                <div class="card-subtext">Seconds ago</div>
            </div>
            
            <!-- System Memory -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">System Memory</div>
                    <div class="card-icon" style="background-color: rgba(139, 92, 246, 0.1); color: #8b5cf6;">
                        <i class="fa-solid fa-memory"></i>
                    </div>
                </div>
                <div class="card-value" id="sys-mem">0 B</div>
                <div class="card-subtext">Allocated Heap</div>
            </div>

            <!-- Goroutines -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Goroutines</div>
                    <div class="card-icon" style="background-color: rgba(236, 72, 153, 0.1); color: #ec4899;">
                        <i class="fa-solid fa-microchip"></i>
                    </div>
                </div>
                <div class="card-value" id="sys-goroutines">0</div>
                <div class="card-subtext">Active Threads</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="grid">
            <div class="card full-width">
                <div class="card-header">
                    <div class="card-title">Real-time Traffic Analysis</div>
                </div>
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Detailed Stats -->
        <div class="card full-width">
            <div class="card-header">
                <div class="card-title">Protocol Breakdown</div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Protocol</th>
                            <th>Inbound Data</th>
                            <th>Outbound Data</th>
                            <th>Current Rate (In)</th>
                            <th>Current Rate (Out)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><i class="fa-solid fa-circle" style="color: var(--accent-primary); font-size: 8px; margin-right: 8px;"></i>TCP</td>
                            <td id="tcp-in-table">0 B</td>
                            <td id="tcp-out-table">0 B</td>
                            <td id="tcp-rate-in">0 B/s</td>
                            <td id="tcp-rate-out">0 B/s</td>
                        </tr>
                        <tr>
                            <td><i class="fa-solid fa-circle" style="color: var(--accent-warning); font-size: 8px; margin-right: 8px;"></i>UDP</td>
                            <td id="udp-in-table">0 B</td>
                            <td id="udp-out-table">0 B</td>
                            <td id="udp-rate-in">0 B/s</td>
                            <td id="udp-rate-out">0 B/s</td>
                        </tr>
                        <tr>
                            <td><i class="fa-solid fa-circle" style="color: var(--accent-info); font-size: 8px; margin-right: 8px;"></i>DNS</td>
                            <td id="dns-queries-table">0</td>
                            <td id="dns-errors-table">0</td>
                            <td id="dns-rate">0/s</td>
                            <td>-</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // --- Chart Configuration ---
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const maxDataPoints = 60;
        const initialData = Array(maxDataPoints).fill(0);

        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = '#334155';

        const trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(maxDataPoints).fill(''),
                datasets: [
                    {
                        label: 'TCP In',
                        data: [...initialData],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'TCP Out',
                        data: [...initialData],
                        borderColor: '#60a5fa',
                        backgroundColor: 'rgba(96, 165, 250, 0.1)',
                        borderWidth: 2,
                        borderDash: [5, 5],
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'UDP In',
                        data: [...initialData],
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'UDP Out',
                        data: [...initialData],
                        borderColor: '#fbbf24',
                        backgroundColor: 'rgba(251, 191, 36, 0.1)',
                        borderWidth: 2,
                        borderDash: [5, 5],
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'DNS Queries',
                        data: [...initialData],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: { intersect: false, mode: 'index' },
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' } }
                },
                plugins: {
                    legend: { position: 'top', align: 'end', labels: { usePointStyle: true, boxWidth: 8 } },
                    tooltip: {
                        backgroundColor: '#1e293b',
                        titleColor: '#f8fafc',
                        bodyColor: '#94a3b8',
                        borderColor: '#334155',
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: function(context) {
                                if (context.dataset.label.includes('DNS')) {
                                    return context.dataset.label + ': ' + context.raw.toFixed(1) + '/s';
                                }
                                return context.dataset.label + ': ' + formatBytes(context.raw * 1024) + '/s';
                            }
                        }
                    }
                }
            }
        });

        // --- Data Fetching & UI Updates ---
        let lastStats = null;
        const fetchInterval = 2000;

        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        function updateStats() {
            fetch('/status?json=true')
                .then(response => response.json())
                .then(data => {
                    // Update Status Badge
                    const statusBadge = document.getElementById('connection-status');
                    const statusText = statusBadge.querySelector('span');
                    if (data.ConnectionHealth === 'Connected') {
                        statusBadge.className = 'status-badge';
                        statusText.textContent = 'Connected';
                    } else {
                        statusBadge.className = 'status-badge disconnected';
                        statusText.textContent = 'Disconnected';
                    }

                    // Update Counters
                    document.getElementById('tcp-active').textContent = data.TcpActiveConnections;
                    document.getElementById('total-in').textContent = formatBytes(data.TcpBytesIn + data.UdpBytesIn);
                    document.getElementById('total-out').textContent = formatBytes(data.TcpBytesOut + data.UdpBytesOut);
                    
                    // Update Last Ping
                    const now = Math.floor(Date.now() / 1000);
                    const diff = now - data.LastSuccessfulPing;
                    document.getElementById('last-ping').textContent = (data.LastSuccessfulPing > 0) ? diff + 's ago' : 'Never';

                    // Update System Stats
                    document.getElementById('sys-mem').textContent = formatBytes(data.SystemMemoryUsage);
                    document.getElementById('sys-goroutines').textContent = data.NumGoroutines;

                    // Update Table
                    document.getElementById('tcp-in-table').textContent = formatBytes(data.TcpBytesIn);
                    document.getElementById('tcp-out-table').textContent = formatBytes(data.TcpBytesOut);
                    document.getElementById('udp-in-table').textContent = formatBytes(data.UdpBytesIn);
                    document.getElementById('udp-out-table').textContent = formatBytes(data.UdpBytesOut);
                    document.getElementById('dns-queries-table').textContent = data.DnsQueries;
                    document.getElementById('dns-errors-table').textContent = data.DnsErrors;

                    // Calculate Rates & Update Chart
                    if (lastStats) {
                        const dt = fetchInterval / 1000;
                        
                        let tcpInRate = (data.TcpBytesIn - lastStats.TcpBytesIn) / dt;
                        let tcpOutRate = (data.TcpBytesOut - lastStats.TcpBytesOut) / dt;
                        let udpInRate = (data.UdpBytesIn - lastStats.UdpBytesIn) / dt;
                        let udpOutRate = (data.UdpBytesOut - lastStats.UdpBytesOut) / dt;
                        let dnsRate = (data.DnsQueries - lastStats.DnsQueries) / dt;

                        // Handle server restarts (counters reset to 0)
                        if (tcpInRate < 0) tcpInRate = 0;
                        if (tcpOutRate < 0) tcpOutRate = 0;
                        if (udpInRate < 0) udpInRate = 0;
                        if (udpOutRate < 0) udpOutRate = 0;
                        if (dnsRate < 0) dnsRate = 0;

                        // Update Rate Labels
                        document.getElementById('rate-in').textContent = formatBytes(tcpInRate + udpInRate) + '/s';
                        document.getElementById('rate-out').textContent = formatBytes(tcpOutRate + udpOutRate) + '/s';
                        
                        document.getElementById('tcp-rate-in').textContent = formatBytes(tcpInRate) + '/s';
                        document.getElementById('tcp-rate-out').textContent = formatBytes(tcpOutRate) + '/s';
                        document.getElementById('udp-rate-in').textContent = formatBytes(udpInRate) + '/s';
                        document.getElementById('udp-rate-out').textContent = formatBytes(udpOutRate) + '/s';
                        document.getElementById('dns-rate').textContent = dnsRate.toFixed(1) + '/s';

                        // Update Chart Data (Convert to KB/s for chart y-axis readability)
                        const datasets = trafficChart.data.datasets;
                        datasets[0].data.push(tcpInRate / 1024);
                        datasets[0].data.shift();
                        datasets[1].data.push(tcpOutRate / 1024);
                        datasets[1].data.shift();
                        datasets[2].data.push(udpInRate / 1024);
                        datasets[2].data.shift();
                        datasets[3].data.push(udpOutRate / 1024);
                        datasets[3].data.shift();
                        datasets[4].data.push(dnsRate);
                        datasets[4].data.shift();
                        
                        trafficChart.update('none'); // 'none' mode for performance
                    }

                    lastStats = data;
                })
                .catch(console.error);
        }

        setInterval(updateStats, fetchInterval);
        updateStats();
    </script>
</body>
</html>
`

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("json") == "true" {
		status := stats.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
		return
	}

	t, err := template.New("status").Parse(statusTemplateHTML)
	if err != nil {
		log.Printf("Error parsing status template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = t.Execute(w, nil) // No data needed for the initial template
	if err != nil {
		log.Printf("Error executing status template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func JsonStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := stats.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
