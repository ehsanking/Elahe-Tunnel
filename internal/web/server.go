package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
)

// StatusProvider defines an interface to get the current tunnel status.
type StatusProvider interface {
	GetStatus() interface{}
}

// Server represents the web panel server.
type Server struct {
	config         *config.Config
	statusProvider StatusProvider
}

// NewServer creates a new web panel server.
func NewServer(cfg *config.Config, provider StatusProvider) *Server {
	return &Server{
		config:         cfg,
		statusProvider: provider,
	}
}

// Start starts the web server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Static files (embedded CSS/JS if needed, for now inline)
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/status", s.handleStatus)

	// Wrap with Basic Auth middleware
	handler := s.basicAuth(mux)

	addr := fmt.Sprintf(":%d", s.config.WebPanelPort)
	logger.Info.Printf("Starting Web Panel on http://localhost%s", addr)
	return http.ListenAndServe(addr, handler)
}

func (s *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != s.config.WebPanelUser || pass != s.config.WebPanelPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elahe Tunnel Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        .status-card { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .card { flex: 1; background: #ecf0f1; padding: 15px; margin: 5px; border-radius: 5px; text-align: center; }
        .card h3 { margin: 0 0 10px; font-size: 1.1em; color: #7f8c8d; }
        .card p { margin: 0; font-size: 1.5em; font-weight: bold; color: #2c3e50; }
        .status-connected { color: #27ae60 !important; }
        .status-disconnected { color: #c0392b !important; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.9em; color: #95a5a6; }
        .refresh-btn { display: block; width: 100%; padding: 10px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 1em; margin-top: 20px; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Elahe Tunnel Dashboard</h1>
        
        <div class="status-card">
            <div class="card">
                <h3>Tunnel Status</h3>
                <p id="tunnel-status">Loading...</p>
            </div>
            <div class="card">
                <h3>Uptime</h3>
                <p id="uptime">0s</p>
            </div>
        </div>

        <div class="status-card">
            <div class="card">
                <h3>Bytes In</h3>
                <p id="bytes-in">0</p>
            </div>
            <div class="card">
                <h3>Bytes Out</h3>
                <p id="bytes-out">0</p>
            </div>
        </div>

        <h2>Connection Details</h2>
        <table>
            <tr><th>Remote Host</th><td id="remote-host">Loading...</td></tr>
            <tr><th>UDP Tunnel</th><td id="udp-status">Loading...</td></tr>
            <tr><th>Last Ping</th><td id="last-ping">Loading...</td></tr>
        </table>

        <button class="refresh-btn" onclick="fetchStatus()">Refresh Status</button>
        
        <div class="footer">
            Elahe Tunnel v1.1 &copy; 2024
        </div>
    </div>

    <script>
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        function fetchStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const statusEl = document.getElementById('tunnel-status');
                    statusEl.textContent = data.connected ? 'Connected' : 'Disconnected';
                    statusEl.className = data.connected ? 'status-connected' : 'status-disconnected';
                    
                    document.getElementById('uptime').textContent = data.uptime;
                    document.getElementById('bytes-in').textContent = formatBytes(data.bytes_in);
                    document.getElementById('bytes-out').textContent = formatBytes(data.bytes_out);
                    document.getElementById('remote-host').textContent = data.remote_host;
                    document.getElementById('udp-status').textContent = data.udp_enabled ? 'Enabled' : 'Disabled';
                    document.getElementById('last-ping').textContent = data.last_ping;
                })
                .catch(err => console.error('Error fetching status:', err));
        }

        // Auto-refresh every 5 seconds
        setInterval(fetchStatus, 5000);
        fetchStatus();
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, tmpl)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := s.statusProvider.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
