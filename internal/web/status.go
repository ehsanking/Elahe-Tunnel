package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

const statusTemplate = `
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
        .card p { margin: 5px 0 0; font-size: 1.8em; font-weight: 600; color: #1a73e8; }
        .health { text-align: center; margin-top: 30px; padding: 15px; border-radius: 8px; }
        .health.ok { background-color: #e8f5e9; color: #2e7d32; border-left: 5px solid #4caf50; }
        .health.fail { background-color: #ffebee; color: #c62828; border-left: 5px solid #f44336; }
    </style>
    <script>
        setTimeout(() => { window.location.reload(); }, 5000);
    </script>
</head>
<body>
    <div class="container">
        <h1>Elahe Tunnel Status</h1>
        <div class="health {{.ConnectionHealthClass}}">
            <p>{{.ConnectionHealth}}</p>
        </div>
        <div class="grid">
            <div class="card">
                <h2>TCP Active Connections</h2>
                <p>{{.TcpActiveConnections}}</p>
            </div>
            <div class="card">
                <h2>TCP Data In</h2>
                <p>{{.TcpBytesIn | formatBytes}}</p>
            </div>
            <div class="card">
                <h2>TCP Data Out</h2>
                <p>{{.TcpBytesOut | formatBytes}}</p>
            </div>
            <div class="card">
                <h2>UDP Data In</h2>
                <p>{{.UdpBytesIn | formatBytes}}</p>
            </div>
            <div class="card">
                <h2>UDP Data Out</h2>
                <p>{{.UdpBytesOut | formatBytes}}</p>
            </div>
        </div>
    </div>
</body>
</html>
`

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	status := stats.Status{
		TcpActiveConnections: stats.GetTcpActiveConnections(),
		TcpBytesIn:           stats.GetTcpBytesIn(),
		TcpBytesOut:          stats.GetTcpBytesOut(),
		UdpBytesIn:           stats.GetUdpBytesIn(),
		UdpBytesOut:          stats.GetUdpBytesOut(),
		LastSuccessfulPing:   stats.GetLastSuccessfulPing(),
	}

	if time.Now().Unix()-status.LastSuccessfulPing < 90 {
		status.ConnectionHealth = "Connected"
	} else {
		status.ConnectionHealth = "Disconnected"
	}

	// Serve JSON if requested
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
		return
	}

	// Otherwise, serve HTML
	tmpl, err := template.New("status").Funcs(template.FuncMap{
		"formatBytes": func(b uint64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
		},
	}).Parse(statusTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	data := struct {
		stats.Status
		ConnectionHealthClass string
	}{
		Status: status,
	}

	if status.ConnectionHealth == "Connected" {
		data.ConnectionHealthClass = "ok"
	} else {
		data.ConnectionHealthClass = "fail"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}
