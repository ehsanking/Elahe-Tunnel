package web

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

const statusTemplateHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elahe Tunnel Status</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 40px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }
        .container { background-color: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 800px; width: 100%; }
        h1 { color: #1a73e8; text-align: center; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .card { background-color: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 5px solid #1a73e8; }
        .card h2 { margin-top: 0; font-size: 1.2em; color: #333; }
        .card p { margin: 10px 0 0; font-size: 1em; color: #5f6368; }
		.card p span { font-size: 1.6em; font-weight: 600; color: #1a73e8; display: block; margin-top: 4px;}
		.rate { font-size: 0.8em !important; color: #5f6368 !important; font-weight: normal !important; }
        .health { text-align: center; margin-top: 30px; padding: 15px; border-radius: 8px; font-size: 1.2em; font-weight: 600;}
        .health.ok { background-color: #e8f5e9; color: #2e7d32; border-left: 5px solid #4caf50; }
        .health.fail { background-color: #ffebee; color: #c62828; border-left: 5px solid #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Elahe Tunnel Status</h1>
		<div id="health-status" class="health">
			Checking connection...
        </div>
        <div class="grid">
            <div class="card">
                <h2>TCP</h2>
				<p>Active Connections: <span id="tcp-active">0</span></p>
				<p>Data In: <span id="tcp-in">0 B</span> <span id="tcp-in-rate" class="rate"></span></p>
				<p>Data Out: <span id="tcp-out">0 B</span> <span id="tcp-out-rate" class="rate"></span></p>
            </div>
            <div class="card">
                <h2>UDP</h2>
				<p>Active Connections: <span id="udp-active">N/A</span></p> 
                <p>Data In: <span id="udp-in">0 B</span> <span id="udp-in-rate" class="rate"></span></p>
                <p>Data Out: <span id="udp-out">0 B</span> <span id="udp-out-rate" class="rate"></span></p>
            </div>
        </div>
    </div>

	<script>
		let lastStats = null;
		const fetchInterval = 5000; // 5 seconds

		function formatBytes(bytes, decimals = 2) {
			if (bytes === 0) return '0 B';
			const k = 1024;
			const dm = decimals < 0 ? 0 : decimals;
			const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
		}

		function updateStats() {
			fetch('/status?json=true')
				.then(response => response.json())
				.then(data => {
					const healthDiv = document.getElementById('health-status');
					healthDiv.textContent = data.ConnectionHealth;
					healthDiv.className = 'health ' + (data.ConnectionHealth === 'Connected' ? 'ok' : 'fail');

					document.getElementById('tcp-active').textContent = data.TcpActiveConnections;
					
					document.getElementById('tcp-in').textContent = formatBytes(data.TcpBytesIn);
					document.getElementById('tcp-out').textContent = formatBytes(data.TcpBytesOut);
					document.getElementById('udp-in').textContent = formatBytes(data.UdpBytesIn);
					document.getElementById('udp-out').textContent = formatBytes(data.UdpBytesOut);

					if (lastStats) {
						const intervalSeconds = fetchInterval / 1000;
						document.getElementById('tcp-in-rate').textContent = '(' + formatBytes((data.TcpBytesIn - lastStats.TcpBytesIn) / intervalSeconds) + '/s)';
						document.getElementById('tcp-out-rate').textContent = '(' + formatBytes((data.TcpBytesOut - lastStats.TcpBytesOut) / intervalSeconds) + '/s)';
						document.getElementById('udp-in-rate').textContent = '(' + formatBytes((data.UdpBytesIn - lastStats.UdpBytesIn) / intervalSeconds) + '/s)';
						document.getElementById('udp-out-rate').textContent = '(' + formatBytes((data.UdpBytesOut - lastStats.UdpBytesOut) / intervalSeconds) + '/s)';
					}
					lastStats = data;
				})
				.catch(error => {
					console.error('Error fetching stats:', error);
					const healthDiv = document.getElementById('health-status');
					healthDiv.textContent = 'Error fetching status';
					healthDiv.className = 'health fail';
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
