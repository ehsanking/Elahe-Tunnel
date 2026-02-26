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
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
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
            --accent-purple: #8b5cf6;
            --border-color: #334155;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: var(--bg-body); color: var(--text-primary); display: flex; min-height: 100vh; }

        /* Sidebar */
        .sidebar { width: 260px; background-color: var(--bg-sidebar); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; padding: 24px; position: fixed; height: 100vh; overflow-y: auto; z-index: 50; }
        .logo { font-size: 1.5rem; font-weight: 800; color: var(--text-primary); margin-bottom: 40px; display: flex; align-items: center; gap: 12px; letter-spacing: -0.5px; }
        .logo i { color: var(--accent-primary); filter: drop-shadow(0 0 8px rgba(59, 130, 246, 0.5)); }
        .nav-item { display: flex; align-items: center; gap: 12px; padding: 14px 16px; color: var(--text-secondary); text-decoration: none; border-radius: 12px; transition: all 0.2s ease; margin-bottom: 8px; font-weight: 600; font-size: 0.95rem; }
        .nav-item:hover { background-color: rgba(255, 255, 255, 0.05); color: var(--text-primary); transform: translateX(4px); }
        .nav-item.active { background-color: var(--accent-primary); color: white; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
        .nav-item i { width: 24px; text-align: center; font-size: 1.1rem; }

        /* Main Content */
        .main-content { flex: 1; margin-left: 260px; padding: 40px; overflow-y: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .page-title { font-size: 2rem; font-weight: 700; letter-spacing: -0.5px; }
        .page-subtitle { color: var(--text-secondary); font-size: 0.9rem; margin-top: 4px; }
        
        .status-badge { padding: 8px 16px; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; display: flex; align-items: center; gap: 8px; background-color: rgba(16, 185, 129, 0.1); color: var(--accent-success); border: 1px solid rgba(16, 185, 129, 0.2); transition: all 0.3s ease; }
        .status-badge.disconnected { background-color: rgba(239, 68, 68, 0.1); color: var(--accent-danger); border-color: rgba(239, 68, 68, 0.2); }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background-color: currentColor; box-shadow: 0 0 8px currentColor; animation: pulse 2s infinite; }

        @keyframes pulse {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
            100% { opacity: 1; transform: scale(1); }
        }

        /* Grid Layouts */
        .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-bottom: 24px; }
        .grid-2-1 { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 24px; }
        
        /* Cards */
        .card { background-color: var(--bg-card); border-radius: 20px; padding: 24px; border: 1px solid var(--border-color); box-shadow: var(--shadow-sm); transition: transform 0.2s, box-shadow 0.2s; position: relative; overflow: hidden; }
        .card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); border-color: rgba(255, 255, 255, 0.1); }
        .card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
        .card-title { font-size: 0.95rem; color: var(--text-secondary); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .card-icon { width: 48px; height: 48px; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; transition: transform 0.3s ease; }
        .card:hover .card-icon { transform: scale(1.1) rotate(5deg); }
        
        .card-value { font-size: 2rem; font-weight: 800; margin-bottom: 8px; letter-spacing: -1px; }
        .card-subtext { font-size: 0.85rem; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; font-weight: 500; }
        
        .trend-up { color: var(--accent-success); display: flex; align-items: center; gap: 4px; }
        .trend-down { color: var(--accent-danger); display: flex; align-items: center; gap: 4px; }

        /* Charts */
        .chart-container { position: relative; height: 320px; width: 100%; }
        .chart-container-sm { position: relative; height: 250px; width: 100%; display: flex; justify-content: center; }

        /* Tables */
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: separate; border-spacing: 0; }
        th { text-align: left; padding: 16px 20px; color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--border-color); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
        td { padding: 16px 20px; border-bottom: 1px solid var(--border-color); color: var(--text-primary); font-size: 0.95rem; font-weight: 500; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background-color: rgba(255, 255, 255, 0.02); }

        .proto-badge { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 8px; font-size: 0.85rem; font-weight: 600; }
        .proto-tcp { background-color: rgba(59, 130, 246, 0.1); color: var(--accent-primary); }
        .proto-udp { background-color: rgba(245, 158, 11, 0.1); color: var(--accent-warning); }
        .proto-dns { background-color: rgba(6, 182, 212, 0.1); color: var(--accent-info); }

        .kill-btn { background-color: rgba(239, 68, 68, 0.1); color: var(--accent-danger); border: 1px solid rgba(239, 68, 68, 0.2); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 600; transition: all 0.2s; }
        .kill-btn:hover { background-color: var(--accent-danger); color: white; }

        /* Responsive */
        @media (max-width: 1024px) {
            .grid-2-1 { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; padding: 20px; }
            .grid-4 { grid-template-columns: 1fr; }
            .page-title { font-size: 1.5rem; }
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
            <i class="fa-solid fa-chart-pie"></i>
            <span>Dashboard</span>
        </a>
        <a href="/connections" class="nav-item">
            <i class="fa-solid fa-network-wired"></i>
            <span>Connections</span>
        </a>
        <a href="/logs" class="nav-item">
            <i class="fa-solid fa-file-lines"></i>
            <span>System Logs</span>
        </a>
        <a href="#" class="nav-item">
            <i class="fa-solid fa-gear"></i>
            <span>Settings</span>
        </a>
        <div style="flex: 1"></div>
        <a href="/logout" class="nav-item" style="color: var(--accent-danger);">
            <i class="fa-solid fa-sign-out-alt"></i>
            <span>Logout</span>
        </a>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="header">
            <div>
                <div class="page-title">Dashboard Overview</div>
                <div class="page-subtitle">Real-time monitoring and statistics</div>
            </div>
            <div id="connection-status" class="status-badge">
                <div class="status-dot"></div>
                <span>Connecting...</span>
            </div>
        </div>

        <!-- Key Metrics -->
        <div class="grid-4">
            <!-- Active Connections -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Active Sessions</div>
                    <div class="card-icon" style="background-color: rgba(59, 130, 246, 0.1); color: var(--accent-primary);">
                        <i class="fa-solid fa-users"></i>
                    </div>
                </div>
                <div class="card-value" id="tcp-active">0</div>
                <div class="card-subtext">TCP Connections</div>
            </div>

            <!-- Total Traffic -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Total Traffic</div>
                    <div class="card-icon" style="background-color: rgba(16, 185, 129, 0.1); color: var(--accent-success);">
                        <i class="fa-solid fa-right-left"></i>
                    </div>
                </div>
                <div class="card-value" id="total-traffic">0 B</div>
                <div class="card-subtext">
                    <span id="total-rate" class="trend-up"><i class="fa-solid fa-bolt"></i> 0 B/s</span>
                </div>
            </div>

            <!-- System Load -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">System Load</div>
                    <div class="card-icon" style="background-color: rgba(139, 92, 246, 0.1); color: var(--accent-purple);">
                        <i class="fa-solid fa-server"></i>
                    </div>
                </div>
                <div class="card-value" id="sys-goroutines">0</div>
                <div class="card-subtext">Active Goroutines</div>
            </div>

            <!-- Uptime/Ping -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Health Check</div>
                    <div class="card-icon" style="background-color: rgba(239, 68, 68, 0.1); color: var(--accent-danger);">
                        <i class="fa-solid fa-heart-pulse"></i>
                    </div>
                </div>
                <div class="card-value" id="last-ping">--</div>
                <div class="card-subtext">Last Heartbeat</div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="grid-2-1">
            <!-- Traffic Chart -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Traffic Analysis (In/Out)</div>
                </div>
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>

            <!-- Protocol Distribution -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Protocol Distribution</div>
                </div>
                <div class="chart-container-sm">
                    <canvas id="protocolChart"></canvas>
                </div>
                <div style="text-align: center; margin-top: 16px; color: var(--text-secondary); font-size: 0.9rem;">
                    Based on total bytes transferred
                </div>
            </div>
        </div>

        <!-- Detailed Stats Table -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Protocol Breakdown</div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Protocol</th>
                            <th>Total Inbound</th>
                            <th>Total Outbound</th>
                            <th>Current Rate (In)</th>
                            <th>Current Rate (Out)</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><div class="proto-badge proto-tcp"><i class="fa-solid fa-circle" style="font-size: 8px;"></i> TCP</div></td>
                            <td id="tcp-in-table">0 B</td>
                            <td id="tcp-out-table">0 B</td>
                            <td id="tcp-rate-in" style="color: var(--accent-success);">0 B/s</td>
                            <td id="tcp-rate-out" style="color: var(--accent-warning);">0 B/s</td>
                            <td><span style="color: var(--accent-success); font-size: 0.85rem;"><i class="fa-solid fa-check-circle"></i> Active</span></td>
                        </tr>
                        <tr>
                            <td><div class="proto-badge proto-udp"><i class="fa-solid fa-circle" style="font-size: 8px;"></i> UDP</div></td>
                            <td id="udp-in-table">0 B</td>
                            <td id="udp-out-table">0 B</td>
                            <td id="udp-rate-in" style="color: var(--accent-success);">0 B/s</td>
                            <td id="udp-rate-out" style="color: var(--accent-warning);">0 B/s</td>
                            <td><span style="color: var(--accent-success); font-size: 0.85rem;"><i class="fa-solid fa-check-circle"></i> Active</span></td>
                        </tr>
                        <tr>
                            <td><div class="proto-badge proto-dns"><i class="fa-solid fa-circle" style="font-size: 8px;"></i> DNS</div></td>
                            <td id="dns-queries-table">0 Queries</td>
                            <td id="dns-errors-table">0 Errors</td>
                            <td id="dns-rate" style="color: var(--accent-info);">0/s</td>
                            <td>-</td>
                            <td><span style="color: var(--accent-success); font-size: 0.85rem;"><i class="fa-solid fa-check-circle"></i> Active</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Active Connections Table -->
        <div class="card" style="margin-top: 24px;">
            <div class="card-header">
                <div class="card-title">Recent Active Connections</div>
                <a href="/connections" style="color: var(--accent-primary); font-size: 0.85rem; text-decoration: none; font-weight: 600;">View All <i class="fa-solid fa-arrow-right"></i></a>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Proxy Name</th>
                            <th>Duration</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="connections-tbody">
                        <tr>
                            <td colspan="4" style="text-align: center; color: var(--text-secondary);">Loading connections...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // --- Chart Configuration ---
        Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = 'rgba(51, 65, 85, 0.5)';

        // Line Chart (Traffic)
        const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
        const maxDataPoints = 60;
        const initialData = Array(maxDataPoints).fill(0);

        const trafficChart = new Chart(ctxTraffic, {
            type: 'line',
            data: {
                labels: Array(maxDataPoints).fill(''),
                datasets: [
                    {
                        label: 'Inbound',
                        data: [...initialData],
                        borderColor: '#10b981',
                        backgroundColor: (context) => {
                            const ctx = context.chart.ctx;
                            const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                            gradient.addColorStop(0, 'rgba(16, 185, 129, 0.2)');
                            gradient.addColorStop(1, 'rgba(16, 185, 129, 0)');
                            return gradient;
                        },
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4
                    },
                    {
                        label: 'Outbound',
                        data: [...initialData],
                        borderColor: '#3b82f6',
                        backgroundColor: (context) => {
                            const ctx = context.chart.ctx;
                            const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                            gradient.addColorStop(0, 'rgba(59, 130, 246, 0.2)');
                            gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
                            return gradient;
                        },
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4
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
                    y: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { callback: (value) => formatBytes(value * 1024) + '/s' }
                    }
                },
                plugins: {
                    legend: { position: 'top', align: 'end', labels: { usePointStyle: true, boxWidth: 8 } },
                    tooltip: {
                        backgroundColor: '#1e293b',
                        titleColor: '#f8fafc',
                        bodyColor: '#94a3b8',
                        borderColor: '#334155',
                        borderWidth: 1,
                        padding: 10,
                        callbacks: {
                            label: (context) => context.dataset.label + ': ' + formatBytes(context.raw * 1024) + '/s'
                        }
                    }
                }
            }
        });

        // Doughnut Chart (Protocol Distribution)
        const ctxProtocol = document.getElementById('protocolChart').getContext('2d');
        const protocolChart = new Chart(ctxProtocol, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#3b82f6', '#f59e0b'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { position: 'bottom', labels: { usePointStyle: true, padding: 20 } },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const value = context.raw;
                                const total = context.chart._metasets[context.datasetIndex].total;
                                const percentage = ((value / total) * 100).toFixed(1) + '%';
                                return context.label + ': ' + formatBytes(value) + ' (' + percentage + ')';
                            }
                        }
                    }
                }
            }
        });

        // --- Data Fetching & UI Updates ---
        let lastStats = null;
        const fetchInterval = 2000;

        function formatBytes(bytes, decimals = 1) {
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
                    
                    const totalBytes = data.TcpBytesIn + data.TcpBytesOut + data.UdpBytesIn + data.UdpBytesOut;
                    document.getElementById('total-traffic').textContent = formatBytes(totalBytes);
                    
                    // Update Last Ping
                    const now = Math.floor(Date.now() / 1000);
                    const diff = now - data.LastSuccessfulPing;
                    document.getElementById('last-ping').textContent = (data.LastSuccessfulPing > 0) ? diff + 's ago' : 'Never';

                    // Update System Stats
                    document.getElementById('sys-goroutines').textContent = data.NumGoroutines;

                    // Update Table
                    document.getElementById('tcp-in-table').textContent = formatBytes(data.TcpBytesIn);
                    document.getElementById('tcp-out-table').textContent = formatBytes(data.TcpBytesOut);
                    document.getElementById('udp-in-table').textContent = formatBytes(data.UdpBytesIn);
                    document.getElementById('udp-out-table').textContent = formatBytes(data.UdpBytesOut);
                    document.getElementById('dns-queries-table').textContent = data.DnsQueries + ' Queries';
                    document.getElementById('dns-errors-table').textContent = data.DnsErrors + ' Errors';

                    // Update Protocol Chart Data
                    const totalTcp = data.TcpBytesIn + data.TcpBytesOut;
                    const totalUdp = data.UdpBytesIn + data.UdpBytesOut;
                    protocolChart.data.datasets[0].data = [totalTcp, totalUdp];
                    protocolChart.update();

                    // Calculate Rates & Update Line Chart
                    if (lastStats) {
                        const dt = fetchInterval / 1000;
                        
                        let tcpInRate = (data.TcpBytesIn - lastStats.TcpBytesIn) / dt;
                        let tcpOutRate = (data.TcpBytesOut - lastStats.TcpBytesOut) / dt;
                        let udpInRate = (data.UdpBytesIn - lastStats.UdpBytesIn) / dt;
                        let udpOutRate = (data.UdpBytesOut - lastStats.UdpBytesOut) / dt;
                        let dnsRate = (data.DnsQueries - lastStats.DnsQueries) / dt;

                        // Handle resets
                        if (tcpInRate < 0) tcpInRate = 0;
                        if (tcpOutRate < 0) tcpOutRate = 0;
                        if (udpInRate < 0) udpInRate = 0;
                        if (udpOutRate < 0) udpOutRate = 0;

                        const totalRate = tcpInRate + tcpOutRate + udpInRate + udpOutRate;
                        document.getElementById('total-rate').innerHTML = '<i class="fa-solid fa-bolt"></i> ' + formatBytes(totalRate) + '/s';

                        // Update Table Rates
                        document.getElementById('tcp-rate-in').textContent = formatBytes(tcpInRate) + '/s';
                        document.getElementById('tcp-rate-out').textContent = formatBytes(tcpOutRate) + '/s';
                        document.getElementById('udp-rate-in').textContent = formatBytes(udpInRate) + '/s';
                        document.getElementById('udp-rate-out').textContent = formatBytes(udpOutRate) + '/s';
                        document.getElementById('dns-rate').textContent = dnsRate.toFixed(1) + '/s';

                        // Update Line Chart (KB/s)
                        const totalInRate = tcpInRate + udpInRate;
                        const totalOutRate = tcpOutRate + udpOutRate;

                        const datasets = trafficChart.data.datasets;
                        datasets[0].data.push(totalInRate / 1024);
                        datasets[0].data.shift();
                        datasets[1].data.push(totalOutRate / 1024);
                        datasets[1].data.shift();
                        
                        trafficChart.update('none');
                    }

                    lastStats = data;
                })
                .catch(console.error);

            // Fetch active connections
            fetch('/connections?json=true')
                .then(response => response.json())
                .then(connections => {
                    const tbody = document.getElementById('connections-tbody');
                    if (!connections || connections.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No active connections</td></tr>';
                        return;
                    }
                    
                    // Sort by newest first and take top 5 for dashboard
                    connections.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));
                    const topConns = connections.slice(0, 5);
                    
                    let html = '';
                    const now = new Date();
                    topConns.forEach(conn => {
                        const startTime = new Date(conn.start_time);
                        const diffSecs = Math.floor((now - startTime) / 1000);
                        
                        let durationStr = '';
                        if (diffSecs < 60) durationStr = diffSecs + 's';
                        else if (diffSecs < 3600) durationStr = Math.floor(diffSecs/60) + 'm ' + (diffSecs%60) + 's';
                        else durationStr = Math.floor(diffSecs/3600) + 'h ' + Math.floor((diffSecs%3600)/60) + 'm';
                        
                        html += '<tr>';
                        html += '<td style="font-family: monospace; font-size: 0.85rem;">' + conn.id.substring(0, 16) + '...</td>';
                        html += '<td>' + conn.proxy_name + '</td>';
                        html += '<td>' + durationStr + '</td>';
                        html += '<td><button class="kill-btn" onclick="killConnection(\'' + conn.id + '\')">Kill</button></td>';
                        html += '</tr>';
                    });
                    tbody.innerHTML = html;
                })
                .catch(console.error);
        }

        function killConnection(id) {
            if (confirm('Are you sure you want to terminate this connection?')) {
                fetch('/kill?id=' + id, { method: 'POST' })
                    .then(response => {
                        if (response.ok) {
                            updateStats(); // Refresh immediately
                        } else {
                            alert('Failed to kill connection.');
                        }
                    });
            }
        }

        setInterval(updateStats, fetchInterval);
        updateStats();
    </script>
</body>
</html>
`

func StatusHandler(w http.ResponseWriter, r *http.Request) {
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
