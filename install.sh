#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Spinner Function ---
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer v3.2 (Final) ${NC}"
echo -e "${GREEN}=========================================${NC}"

# 1. Install Dependencies
apt-get update -qq && apt-get install -y -qq unzip curl file &> /dev/null

# Enable TCP Fast Open in kernel
if [ -f /proc/sys/net/ipv4/tcp_fastopen ]; then
    echo 3 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || true
fi

# 2. Download Source Code
echo -n "Downloading Elahe Tunnel source code..."
(
    rm -rf Elahe-Tunnel-main elahe-tunnel-main main.zip
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip" || \
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://mirror.ghproxy.com/https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"
    unzip -o -q main.zip
) &> /dev/null &
spinner $!
wait $!

if [ -d "Elahe-Tunnel-main" ]; then
    SOURCE_DIR="Elahe-Tunnel-main"
elif [ -d "elahe-tunnel-main" ]; then
    SOURCE_DIR="elahe-tunnel-main"
else
    echo -e "\n${RED}Failed to download source code.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 3. Install Go
if ! command -v go &> /dev/null || [ "$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2)" -lt 24 ]; then
    echo -n "Installing Go 1.24.0..."
    (
        rm -rf /usr/local/go
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        URL="https://go.dev/dl/go1.24.0.linux-${ARCH}.tar.gz"
        curl -L -o /tmp/go.tar.gz "$URL"
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    ) &> /dev/null &
    spinner $!
    wait $!
    echo -e " ${GREEN}OK${NC}"
fi
export PATH=/usr/local/go/bin:$PATH

# 4. Overwrite source files and Compile
echo -n "Applying patches and compiling..."
cd "$SOURCE_DIR"

# --- Create/Overwrite All Corrected Files ---

mkdir -p internal/stats
cat <<'EOF' > internal/stats/stats.go
package stats

import (
	"sync/atomic"
	"time"
)

var (
	tcpActiveConnections int64
	tcpBytesIn           uint64
	tcpBytesOut          uint64
	udpBytesIn           uint64
	udpBytesOut          uint64
	dnsQueries           uint64
	dnsErrors            uint64
	lastSuccessfulPing   int64
)

func AddTcpActiveConnection()    { atomic.AddInt64(&tcpActiveConnections, 1) }
func RemoveTcpActiveConnection() { atomic.AddInt64(&tcpActiveConnections, -1) }
func GetTcpActiveConnections() int64 { return atomic.LoadInt64(&tcpActiveConnections) }
func AddTcpBytesIn(n uint64)     { atomic.AddUint64(&tcpBytesIn, n) }
func AddTcpBytesOut(n uint64)    { atomic.AddUint64(&tcpBytesOut, n) }
func GetTcpBytesIn() uint64      { return atomic.LoadUint64(&tcpBytesIn) }
func GetTcpBytesOut() uint64     { return atomic.LoadUint64(&tcpBytesOut) }
func AddUdpBytesIn(n uint64)     { atomic.AddUint64(&udpBytesIn, n) }
func AddUdpBytesOut(n uint64)    { atomic.AddUint64(&udpBytesOut, n) }
func GetUdpBytesIn() uint64      { return atomic.LoadUint64(&udpBytesIn) }
func GetUdpBytesOut() uint64     { return atomic.LoadUint64(&udpBytesOut) }
func AddDnsQuery()               { atomic.AddUint64(&dnsQueries, 1) }
func AddDnsError()               { atomic.AddUint64(&dnsErrors, 1) }
func GetDnsQueries() uint64      { return atomic.LoadUint64(&dnsQueries) }
func GetDnsErrors() uint64       { return atomic.LoadUint64(&dnsErrors) }
func SetLastSuccessfulPing(t int64) { atomic.StoreInt64(&lastSuccessfulPing, t) }
func GetLastSuccessfulPing() int64  { return atomic.LoadInt64(&lastSuccessfulPing) }

type Status struct {
	TcpActiveConnections int64  `json:"TcpActiveConnections"`
	TcpBytesIn           uint64 `json:"TcpBytesIn"`
	TcpBytesOut          uint64 `json:"TcpBytesOut"`
	UdpBytesIn           uint64 `json:"UdpBytesIn"`
	UdpBytesOut          uint64 `json:"UdpBytesOut"`
	DnsQueries           uint64 `json:"DnsQueries"`
	DnsErrors            uint64 `json:"DnsErrors"`
	LastSuccessfulPing   int64  `json:"LastSuccessfulPing"`
	ConnectionHealth     string `json:"ConnectionHealth"`
}

func GetStatus() Status {
	status := Status{
		TcpActiveConnections: GetTcpActiveConnections(),
		TcpBytesIn:           GetTcpBytesIn(),
		TcpBytesOut:          GetTcpBytesOut(),
		UdpBytesIn:           GetUdpBytesIn(),
		UdpBytesOut:          GetUdpBytesOut(),
		DnsQueries:           GetDnsQueries(),
		DnsErrors:            GetDnsErrors(),
		LastSuccessfulPing:   GetLastSuccessfulPing(),
	}

	if time.Now().Unix()-status.LastSuccessfulPing < 90 {
		status.ConnectionHealth = "Connected"
	} else {
		status.ConnectionHealth = "Disconnected"
	}
	return status
}
EOF

mkdir -p internal/web
cat <<'EOF' > internal/web/server.go
package web

import (
	"fmt"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/config"
)

func StartServer(cfg *config.Config) {
	if !cfg.WebPanelEnabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", basicAuth(StatusHandler, cfg.WebPanelUser, cfg.WebPanelPass, "Elahe Tunnel Panel"))
	mux.HandleFunc("/live", basicAuth(StatusHandler, cfg.WebPanelUser, cfg.WebPanelPass, "Elahe Tunnel Panel"))

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	fmt.Printf("Web panel starting on http://%s\n", addr)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		fmt.Printf("Failed to start web panel: %v\n", err)
	}
}

func basicAuth(handler http.HandlerFunc, username, password, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized.\n"))
			return
		}

		handler(w, r)
	}
}
EOF

cat <<'EOF' > internal/web/status.go
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
    <title>Elahe Tunnel Status</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        /* --- Theme Variables --- */
        :root {
            /* Colors */
            --color-bg: #0f172a;
            --color-surface: #1e293b;
            --color-border: rgba(255, 255, 255, 0.1);
            --color-text-primary: #f1f5f9;
            --color-text-secondary: #94a3b8;
            --color-accent: #3b82f6;
            --color-success: #10b981;
            --color-danger: #ef4444;
            
            /* Success/Danger Muted (for badges) */
            --color-success-muted: rgba(6, 78, 59, 0.8);
            --color-danger-muted: rgba(127, 29, 29, 0.8);
            --color-success-text: #34d399;
            --color-danger-text: #f87171;

            /* Spacing & Sizing */
            --spacing-xs: 4px;
            --spacing-sm: 8px;
            --spacing-md: 16px;
            --spacing-lg: 24px;
            --spacing-xl: 32px;
            --container-max-width: 900px;

            /* Effects */
            --radius-sm: 8px;
            --radius-md: 16px;
            --radius-full: 9999px;
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --transition-base: all 0.3s ease;
        }

        /* --- Base Styles --- */
        body { 
            font-family: 'Inter', -apple-system, system-ui, sans-serif; 
            background-color: var(--color-bg); 
            color: var(--color-text-primary); 
            margin: 0; 
            padding: var(--spacing-lg); 
            display: flex; 
            justify-content: center; 
            min-height: 100vh; 
            line-height: 1.5;
        }

        /* --- Layout --- */
        .container { 
            max-width: var(--container-max-width); 
            width: 100%; 
            margin-top: 40px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: var(--spacing-xl);
        }

        .grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: var(--spacing-lg); 
        }

        /* --- Typography --- */
        h1 { 
            font-size: 24px;
            font-weight: 700;
            margin: 0;
            letter-spacing: -0.02em;
        }

        /* --- Components: Health Badge --- */
        .health-badge {
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
            padding: 6px 16px;
            border-radius: var(--radius-full);
            font-size: 14px;
            font-weight: 600;
            transition: var(--transition-base);
        }

        .health-badge.ok {
            background-color: var(--color-success-muted);
            color: var(--color-success-text);
        }

        .health-badge.fail {
            background-color: var(--color-danger-muted);
            color: var(--color-danger-text);
        }

        .pulse {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: currentColor;
        }

        .ok .pulse { animation: pulse-green 2s infinite; }
        .fail .pulse { animation: pulse-red 2s infinite; }

        /* --- Components: Cards & Stats --- */
        .card { 
            background-color: var(--color-surface); 
            padding: var(--spacing-lg); 
            border-radius: var(--radius-md); 
            box-shadow: var(--shadow-md);
            border: 1px solid var(--color-border);
        }

        .card h2 { 
            margin: 0 0 var(--spacing-md) 0; 
            font-size: 14px; 
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--color-text-secondary); 
        }

        .stat-group {
            margin-bottom: var(--spacing-md);
        }

        .stat-group:last-child {
            margin-bottom: 0;
        }

        .stat-label {
            font-size: 13px;
            color: var(--color-text-secondary);
            margin-bottom: var(--spacing-xs);
        }

        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--color-text-primary);
            display: flex;
            align-items: baseline;
            gap: var(--spacing-xs);
        }

        .stat-unit {
            font-size: 14px;
            font-weight: 500;
            color: var(--color-text-secondary);
        }

        .rate { 
            font-size: 12px; 
            color: var(--color-success); 
            font-weight: 600;
            margin-top: var(--spacing-xs);
            display: flex;
            align-items: center;
            gap: var(--spacing-xs);
        }

        /* --- Indicators --- */
        .live-indicator {
            display: inline-block;
            width: 6px;
            height: 6px;
            background-color: var(--color-danger);
            border-radius: 50%;
            margin-right: var(--spacing-xs);
            animation: blink 1s infinite;
        }

        /* --- Animations --- */
        @keyframes pulse-green {
            0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
            100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        @keyframes pulse-red {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        @keyframes blink {
            0% { opacity: 1; }
            50% { opacity: 0.3; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Elahe Tunnel <span style="font-size: 12px; color: var(--color-text-secondary); font-weight: 400; margin-left: 8px;"><span class="live-indicator"></span>LIVE</span></h1>
            <div id="health-status" class="health-badge">
                <div class="pulse"></div>
                <div style="display: flex; flex-direction: column; align-items: flex-start; line-height: 1.2;">
                    <span id="health-text">Checking...</span>
                    <span id="last-seen" style="font-size: 10px; opacity: 0.7; font-weight: 400;"></span>
                </div>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <h2>TCP Traffic</h2>
                <div class="stat-group">
                    <div class="stat-label">Active Connections</div>
                    <div class="stat-value" id="tcp-active">0</div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Data Inbound</div>
                    <div class="stat-value" id="tcp-in">0 <span class="stat-unit">B</span></div>
                    <div id="tcp-in-rate" class="rate"></div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Data Outbound</div>
                    <div class="stat-value" id="tcp-out">0 <span class="stat-unit">B</span></div>
                    <div id="tcp-out-rate" class="rate"></div>
                </div>
            </div>

            <div class="card">
                <h2>UDP Traffic</h2>
                <div class="stat-group">
                    <div class="stat-label">Status</div>
                    <div class="stat-value" style="font-size: 18px;">Active</div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Data Inbound</div>
                    <div class="stat-value" id="udp-in">0 <span class="stat-unit">B</span></div>
                    <div id="udp-in-rate" class="rate"></div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Data Outbound</div>
                    <div class="stat-value" id="udp-out">0 <span class="stat-unit">B</span></div>
                    <div id="udp-out-rate" class="rate"></div>
                </div>
            </div>

            <div class="card">
                <h2>Total Traffic</h2>
                <div class="stat-group">
                    <div class="stat-label">Total Data Transferred</div>
                    <div class="stat-value" id="total-bytes">0 <span class="stat-unit">B</span></div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Combined Rate</div>
                    <div id="total-rate" class="rate" style="font-size: 16px;"></div>
                </div>
            </div>

            <div class="card">
                <h2>DNS Statistics</h2>
                <div class="stat-group">
                    <div class="stat-label">Total Queries</div>
                    <div class="stat-value" id="dns-queries">0</div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Error Rate</div>
                    <div class="stat-value" id="dns-error-rate">0.0%</div>
                </div>
                <div class="stat-group">
                    <div class="stat-label">Errors</div>
                    <div class="stat-value" id="dns-errors" style="color: var(--color-danger);">0</div>
                </div>
            </div>
            <div class="card" style="grid-column: 1 / -1;">
                <h2>Traffic History</h2>
                <div style="position: relative; height: 200px; width: 100%;">
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>
        </div>
    </div>

	<script>
		let lastStats = null;
		const fetchInterval = 1000;
        
        // Chart.js Setup
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const maxDataPoints = 60; // 60 seconds of history
        
        const chartConfig = {
            type: 'line',
            data: {
                labels: Array(maxDataPoints).fill(''),
                datasets: [
                    {
                        label: 'TCP Inbound (KB/s)',
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        borderWidth: 2,
                        pointRadius: 0,
                        fill: true,
                        tension: 0.4,
                        data: Array(maxDataPoints).fill(0)
                    },
                    {
                        label: 'TCP Outbound (KB/s)',
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        borderWidth: 2,
                        pointRadius: 0,
                        fill: true,
                        tension: 0.4,
                        data: Array(maxDataPoints).fill(0)
                    },
                    {
                        label: 'UDP Inbound (KB/s)',
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        borderWidth: 2,
                        pointRadius: 0,
                        fill: true,
                        tension: 0.4,
                        data: Array(maxDataPoints).fill(0)
                    },
                    {
                        label: 'UDP Outbound (KB/s)',
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        borderWidth: 2,
                        pointRadius: 0,
                        fill: true,
                        tension: 0.4,
                        data: Array(maxDataPoints).fill(0)
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 0 },
                interaction: { intersect: false, mode: 'index' },
                scales: {
                    x: { display: false },
                    y: { 
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#e5e7eb', usePointStyle: true, boxWidth: 8 }
                    }
                }
            }
        };
        const trafficChart = new Chart(ctx, chartConfig);

        function updateChart(tcpInRate, tcpOutRate, udpInRate, udpOutRate) {
            // Convert to KB/s
            const tcpInKBps = tcpInRate / 1024;
            const tcpOutKBps = tcpOutRate / 1024;
            const udpInKBps = udpInRate / 1024;
            const udpOutKBps = udpOutRate / 1024;
            
            trafficChart.data.datasets[0].data.push(tcpInKBps);
            trafficChart.data.datasets[0].data.shift();
            
            trafficChart.data.datasets[1].data.push(tcpOutKBps);
            trafficChart.data.datasets[1].data.shift();
            
            trafficChart.data.datasets[2].data.push(udpInKBps);
            trafficChart.data.datasets[2].data.shift();
            
            trafficChart.data.datasets[3].data.push(udpOutKBps);
            trafficChart.data.datasets[3].data.shift();
            
            trafficChart.update();
        }

		function formatBytes(bytes) {
			if (bytes === 0) return { val: '0', unit: 'B' };
			const k = 1024;
			const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return {
                val: parseFloat((bytes / Math.pow(k, i)).toFixed(2)),
                unit: sizes[i]
            };
		}

        function setStat(id, bytes) {
            const f = formatBytes(bytes);
            document.getElementById(id).innerHTML = f.val + ' <span class="stat-unit">' + f.unit + '</span>';
        }

        function setRate(id, current, last, dt, icon) {
            const rate = (current - last) / dt;
            if (rate > 0) {
                const f = formatBytes(rate);
                document.getElementById(id).textContent = icon + ' ' + f.val + ' ' + f.unit + '/s';
            } else {
                document.getElementById(id).textContent = '';
            }
        }

		function updateStats() {
			fetch('/?json=true')
				.then(response => response.json())
				.then(data => {
					const healthBadge = document.getElementById('health-status');
                    const healthText = document.getElementById('health-text');
                    const lastSeen = document.getElementById('last-seen');
                    
					healthText.textContent = data.ConnectionHealth;
					healthBadge.className = 'health-badge ' + (data.ConnectionHealth === 'Connected' ? 'ok' : 'fail');
                    
                    if (data.LastSuccessfulPing > 0) {
                        const secondsAgo = Math.floor(Date.now() / 1000 - data.LastSuccessfulPing);
                        lastSeen.textContent = secondsAgo < 5 ? 'Just now' : secondsAgo + 's ago';
                    } else {
                        lastSeen.textContent = 'Never';
                    }

					document.getElementById('tcp-active').textContent = data.TcpActiveConnections;
					
					setStat('tcp-in', data.TcpBytesIn);
					setStat('tcp-out', data.TcpBytesOut);
					setStat('udp-in', data.UdpBytesIn);
					setStat('udp-out', data.UdpBytesOut);

                    const totalBytes = data.TcpBytesIn + data.TcpBytesOut + data.UdpBytesIn + data.UdpBytesOut;
                    setStat('total-bytes', totalBytes);

					document.getElementById('dns-queries').textContent = data.DnsQueries;
					document.getElementById('dns-errors').textContent = data.DnsErrors;

					if (data.DnsQueries > 0) {
						const rate = (data.DnsErrors / data.DnsQueries) * 100;
						document.getElementById('dns-error-rate').textContent = rate.toFixed(1) + '%';
						document.getElementById('dns-error-rate').style.color = rate > 10 ? 'var(--color-danger)' : 'var(--color-success)';
					} else {
						document.getElementById('dns-error-rate').textContent = '0.0%';
						document.getElementById('dns-error-rate').style.color = 'var(--color-text-primary)';
					}

					if (lastStats) {
						const dt = fetchInterval / 1000;
						setRate('tcp-in-rate', data.TcpBytesIn, lastStats.TcpBytesIn, dt, '↑');
						setRate('tcp-out-rate', data.TcpBytesOut, lastStats.TcpBytesOut, dt, '↓');
						setRate('udp-in-rate', data.UdpBytesIn, lastStats.UdpBytesIn, dt, '↑');
						setRate('udp-out-rate', data.UdpBytesOut, lastStats.UdpBytesOut, dt, '↓');

                        const lastTotal = lastStats.TcpBytesIn + lastStats.TcpBytesOut + lastStats.UdpBytesIn + lastStats.UdpBytesOut;
                        setRate('total-rate', totalBytes, lastTotal, dt, '⇄');
                        
                        const tcpInRate = (data.TcpBytesIn - lastStats.TcpBytesIn) / dt;
                        const tcpOutRate = (data.TcpBytesOut - lastStats.TcpBytesOut) / dt;
                        const udpInRate = (data.UdpBytesIn - lastStats.UdpBytesIn) / dt;
                        const udpOutRate = (data.UdpBytesOut - lastStats.UdpBytesOut) / dt;
                        
                        updateChart(
                            Math.max(0, tcpInRate),
                            Math.max(0, tcpOutRate),
                            Math.max(0, udpInRate),
                            Math.max(0, udpOutRate)
                        );
					}
					lastStats = data;
				})
				.catch(err => {
					document.getElementById('health-text').textContent = 'Offline';
					document.getElementById('health-status').className = 'health-badge fail';
				});
		}

		document.addEventListener('DOMContentLoaded', () => {
			updateStats();
			setInterval(updateStats, fetchInterval);
		});
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
EOF

cat <<'EOF' > internal/config/config.go
package config

import (
	"encoding/json"
	"os"
)

const ConfigFileName = "search_tunnel_config.json"

type Config struct {
	NodeType           string `json:"node_type"`
	ConnectionKey      string `json:"connection_key"`
	RemoteHost         string `json:"remote_host,omitempty"`
	DnsProxyEnabled    bool   `json:"dns_proxy_enabled,omitempty"`
	DestinationHost    string `json:"destination_host,omitempty"`
	UdpProxyEnabled    bool   `json:"udp_proxy_enabled,omitempty"`
	DestinationUdpHost string `json:"destination_udp_host,omitempty"`
	TunnelListenAddr   string `json:"tunnel_listen_addr,omitempty"`
	TunnelListenKey    string `json:"tunnel_listen_key,omitempty"`
	WebPanelEnabled    bool   `json:"web_panel_enabled,omitempty"`
	WebPanelUser       string `json:"web_panel_user,omitempty"`
	WebPanelPass       string `json:"web_panel_pass,omitempty"`
	WebPanelPort       int    `json:"web_panel_port,omitempty"`
}

func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFileName, data, 0600)
}

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
EOF

cat <<'EOF' > cmd/VERSION
v3.2.0
EOF

cat <<'EOF' > cmd/version.go
package cmd

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed VERSION
var versionFile string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Elahe Tunnel",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Elahe Tunnel %s\n", strings.TrimSpace(versionFile))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
EOF

cat <<'EOF' > cmd/setup.go
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup [internal | external]",
	Short: "Initial setup for the Elahe Tunnel.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		setupType := args[0]
		switch setupType {
		case "internal":
			setupInternal()
		case "external":
			setupExternal()
		default:
			fmt.Printf("Error: Invalid setup type '%s'.\n", setupType)
			os.Exit(1)
		}
	},
}

func setupExternal() {
	fmt.Println("Setting up as an external server...")
	key, _ := crypto.GenerateKey()
	encodedKey := crypto.EncodeKeyToBase64(key)
	certPEM, keyPEM, _ := crypto.GenerateTLSConfig()
	os.WriteFile("cert.pem", certPEM, 0644)
	os.WriteFile("key.pem", keyPEM, 0600)

	cfg := &config.Config{
		NodeType:      "external",
		ConnectionKey: encodedKey,
	}
	config.SaveConfig(cfg)

	fmt.Println("✅ External server setup complete.")
	fmt.Printf("\n🔑 Your connection key is:\n\n    %s\n\n", encodedKey)
}

func setupInternal() {
	fmt.Println("Setting up as an internal server...")
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the IP of your external server: ")
	host, _ := reader.ReadString('\n')

	fmt.Print("Enter the connection key: ")
	key, _ := reader.ReadString('\n')

	cfg := &config.Config{
		NodeType:      "internal",
		ConnectionKey: strings.TrimSpace(key),
		RemoteHost:    strings.TrimSpace(host),
	}

	fmt.Print("Enable Web Panel? (y/N): ")
	enableWeb, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(enableWeb)) == "y" {
		cfg.WebPanelEnabled = true
		fmt.Print("Enter Web Panel Port (default 8080): ")
		portStr, _ := reader.ReadString('\n')
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			cfg.WebPanelPort = 8080
		} else {
			cfg.WebPanelPort = port
		}

		fmt.Print("Enter Web Panel Username (default admin): ")
		user, _ := reader.ReadString('\n')
		cfg.WebPanelUser = strings.TrimSpace(user)
		if cfg.WebPanelUser == "" {
			cfg.WebPanelUser = "admin"
		}

		fmt.Print("Enter Web Panel Password: ")
		pass, _ := reader.ReadString('\n')
		cfg.WebPanelPass = strings.TrimSpace(pass)
	}

	config.SaveConfig(cfg)
	fmt.Println("\n✅ Internal server setup complete.")
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
EOF

cat <<'EOF' > cmd/run.go
package cmd

import (
	"fmt"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Elahe Tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		// Override config with flags if they are set
		if cmd.Flags().Changed("remote-host") {
			cfg.RemoteHost, _ = cmd.Flags().GetString("remote-host")
		}
		if cmd.Flags().Changed("web-panel-port") {
			cfg.WebPanelPort, _ = cmd.Flags().GetInt("web-panel-port")
		}
		if cmd.Flags().Changed("dns-proxy-enabled") {
			cfg.DnsProxyEnabled, _ = cmd.Flags().GetBool("dns-proxy-enabled")
		}

		switch cfg.NodeType {
		case "internal":
			tunnel.RunClient(cfg)
		case "external":
			key, _ := crypto.DecodeBase64Key(cfg.ConnectionKey)
			tunnel.RunServer(key)
		default:
			fmt.Printf("Error: Invalid node type '%s'. Please run setup first.\n", cfg.NodeType)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Add flags for overriding config values
	runCmd.Flags().String("remote-host", "", "Override the remote host IP or domain")
	runCmd.Flags().Int("web-panel-port", 0, "Override the web panel port")
	runCmd.Flags().Bool("dns-proxy-enabled", false, "Override the DNS proxy setting")
}
EOF

cat <<'EOF' > cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "elahe-tunnel",
	Short: "Elahe Tunnel: A tool for creating secure tunnels over HTTP.",
	Long:  `Elahe Tunnel is a client/server application that allows you to tunnel TCP traffic over a masqueraded HTTP connection.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
}
EOF

mkdir -p internal/tunnel

cat <<'EOF' > internal/tunnel/ping.go
package tunnel

import (
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

func handlePingRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		decrypted, err := crypto.Decrypt(encrypted, key)
		if err != nil || string(decrypted) != "ping" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		stats.SetLastSuccessfulPing(time.Now().Unix())

		encryptedResp, _ := crypto.Encrypt([]byte("pong"), key)
		masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
	}
}
EOF

cat <<'EOF' > internal/tunnel/client.go
package tunnel

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/ehsanking/elahe-tunnel/internal/web"
)

func RunClient(cfg *config.Config) error {
	if cfg.WebPanelEnabled {
		go web.StartServer(cfg)
	}

	key, _ := crypto.DecodeBase64Key(cfg.ConnectionKey)

	netDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// TCP_FASTOPEN_CONNECT = 30
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 30, 1)
			})
		},
	}

	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         netDialer.DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	httpClient := &http.Client{Transport: tr}

	go manageConnection(httpClient, cfg, key)

	if cfg.DnsProxyEnabled {
		go runDnsProxy(cfg, httpClient, key)
	}

	localListener, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		return fmt.Errorf("failed to listen on local port: %v", err)
	}
	defer localListener.Close()

	logger.Info.Println("SOCKS5 proxy listening on 127.0.0.1:1080")

	for {
		localConn, err := localListener.Accept()
		if err != nil {
			continue
		}
		stats.AddTcpActiveConnection()
		go handleClientConnection(localConn, httpClient, cfg, key)
	}
}

func handleClientConnection(localConn net.Conn, httpClient *http.Client, cfg *config.Config, key []byte) {
	defer localConn.Close()
	defer stats.RemoveTcpActiveConnection()

	// SOCKS5 handshake
	if err := socks5Handshake(localConn); err != nil {
		return
	}

	// Read destination address
	destination, err := getSocks5Destination(localConn)
	if err != nil {
		return
	}

	payload := []byte(destination + "\n")
	encrypted, _ := crypto.Encrypt(payload, key)
	req, _ := masquerade.WrapInHttpRequest(encrypted, cfg.RemoteHost)

	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		written, _ := io.Copy(localConn, resp.Body)
		stats.AddTcpBytesOut(uint64(written))
	}()

	go func() {
		defer wg.Done()
		io.Copy(io.Discard, localConn)
	}()

	wg.Wait()
}

func manageConnection(httpClient *http.Client, cfg *config.Config, key []byte) {
	for {
		ping(httpClient, cfg, key)
		time.Sleep(30 * time.Second) // Health check interval
	}
}

func ping(httpClient *http.Client, cfg *config.Config, key []byte) {
	encrypted, _ := crypto.Encrypt([]byte("ping"), key)
	req, _ := masquerade.WrapInHttpRequest(encrypted, cfg.RemoteHost)

	resp, err := httpClient.Do(req)
	if err != nil {
		stats.SetLastSuccessfulPing(0)
		return
	}
	defer resp.Body.Close()

	encryptedResp, _ := masquerade.UnwrapFromHttpResponse(resp)
	decrypted, err := crypto.Decrypt(encryptedResp, key)

	if err == nil && string(decrypted) == "pong" {
		stats.SetLastSuccessfulPing(time.Now().Unix())
	}
}

func runDnsProxy(cfg *config.Config, httpClient *http.Client, key []byte) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err != nil {
		logger.Error.Printf("Failed to resolve DNS proxy address: %v\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Error.Printf("Failed to listen for DNS queries: %v\n", err)
		return
	}
	defer conn.Close()

	logger.Info.Println("DNS proxy listening on 127.0.0.1:53")

	buf := make([]byte, 512)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		stats.AddDnsQuery()
		go func(query []byte, addr *net.UDPAddr) {
			resp, err := forwardDnsQuery(query, cfg, httpClient, key)
			if err != nil {
				stats.AddDnsError()
				return
			}
			conn.WriteToUDP(resp, addr)
		}(append([]byte(nil), buf[:n]...), remoteAddr)
	}
}

func forwardDnsQuery(query []byte, cfg *config.Config, httpClient *http.Client, key []byte) ([]byte, error) {
	// Encrypt DNS query using AES-GCM (via crypto package)
	encrypted, err := crypto.Encrypt(query, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DNS query: %v", err)
	}

	req, err := masquerade.WrapInHttpRequest(encrypted, cfg.RemoteHost)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap DNS query in HTTP request: %v", err)
	}
	req.Header.Set("X-Tunnel-Type", "dns")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS query: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	encryptedResp, err := masquerade.UnwrapFromHttpResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DNS response: %v", err)
	}

	// Decrypt DNS response using AES-GCM (via crypto package)
	return crypto.Decrypt(encryptedResp, key)
}

// --- SOCKS5 Helper Functions ---
func socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 257)
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}
	// Respond that no authentication is required
	conn.Write([]byte{0x05, 0x00})
	return nil
}

func getSocks5Destination(conn net.Conn) (string, error) {
	buf := make([]byte, 257)
	_, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	// CMD (1 byte), RSV (1 byte), ATYP (1 byte)
	// We only support domain name for now
	if buf[3] != 0x03 {
		return "", fmt.Errorf("unsupported address type")
	}
	domainLen := int(buf[4])
	domain := string(buf[5 : 5+domainLen])
	port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
	return fmt.Sprintf("%s:%d", domain, port), nil
}
EOF

cat <<'EOF' > internal/tunnel/server.go
package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/pion/dtls/v2"
	"golang.org/x/time/rate"
)

func rateLimit(next http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(10), 50)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RunServer(key []byte) error {
	pingHandler := http.HandlerFunc(handlePingRequest(key))
	http.Handle("/favicon.ico", rateLimit(pingHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", rateLimit(tunnelHandler))

	go runDtlsServer(key)

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// TCP_FASTOPEN = 23
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 23, 1)
			})
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp", ":443")
	if err != nil {
		return err
	}

	logger.Info.Println("External server listening on :443 (TCP Fast Open enabled)")
	return http.ServeTLS(ln, nil, "cert.pem", "key.pem")
}

func runDtlsServer(key []byte) {
	udpAddr, _ := net.ResolveUDPAddr("udp", ":443")
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	dtlsListener, _ := dtls.Listen("udp", udpAddr, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})

	for {
		conn, _ := dtlsListener.Accept()
		go handleDtlsConnection(conn, key)
	}
}

func handleDtlsConnection(conn net.Conn, key []byte) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
	destination := string(parts[0])
	payload := parts[1]
	stats.AddUdpBytesIn(uint64(len(payload)))

	targetConn, _ := net.DialTimeout("udp", destination, 5*time.Second)
	defer targetConn.Close()
	targetConn.Write(payload)

	respBuf := make([]byte, 4096)
	n, _ = targetConn.Read(respBuf)
	response := append([]byte(destination+"\n"), respBuf[:n]...)
	bytesWritten, _ := conn.Write(response)
	stats.AddUdpBytesOut(uint64(bytesWritten))
}

func handleTunnelRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, _ := masquerade.UnwrapFromHttpRequest(r)
		decrypted, _ := crypto.Decrypt(encrypted, key)

		if r.Header.Get("X-Tunnel-Type") == "dns" {
			handleDnsRequest(w, decrypted, key)
			return
		}

		stats.AddTcpBytesIn(uint64(len(decrypted)))

		parts := bytes.SplitN(decrypted, []byte("\n"), 2)
		destination := string(parts[0])
		payload := parts[1]

		targetConn, _ := net.DialTimeout("tcp", destination, 5*time.Second)
		defer targetConn.Close()
		targetConn.Write(payload)

		respData, _ := io.ReadAll(targetConn)
		encryptedResp, _ := crypto.Encrypt(respData, key)
		stats.AddTcpBytesOut(uint64(len(encryptedResp)))

		masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
	}
}

func handleDnsRequest(w http.ResponseWriter, query []byte, key []byte) {
	stats.AddDnsQuery()
	// Forward to a real DNS server
	dnsServer := "8.8.8.8:53"
	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		stats.AddDnsError()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		stats.AddDnsError()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		stats.AddDnsError()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	encryptedResp, _ := crypto.Encrypt(resp[:n], key)
	masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
}
EOF

( 
    export GOPROXY=https://goproxy.io,direct
    export GOTOOLCHAIN=local
    go mod tidy
    go build -o elahe-tunnel -ldflags "-s -w" .
) &
spinner $!
wait $!

if [ ! -f "elahe-tunnel" ]; then
    echo -e "\n${RED}Compilation failed.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 5. Install Binary and Cleanup
echo -n "Installing binary..."
mv elahe-tunnel /usr/local/bin/
chmod +x /usr/local/bin/elahe-tunnel
cd ..
rm -rf "$SOURCE_DIR" main.zip
echo -e " ${GREEN}OK${NC}"

# 6. Run Setup
echo -e "\n${GREEN}✅ Installation Complete!${NC}"
echo -e "Starting setup wizard...\n"
sleep 1
elahe-tunnel setup external
