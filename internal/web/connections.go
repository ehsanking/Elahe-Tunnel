package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
)

const connectionsTemplateHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Connections - Elahe Tunnel</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-body: #0f172a;
            --bg-sidebar: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-primary: #3b82f6;
            --border-color: #334155;
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
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .page-title { font-size: 1.8rem; font-weight: 600; }

        /* Table */
        .table-container { background-color: var(--bg-card); border-radius: 16px; padding: 24px; border: 1px solid var(--border-color); overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px; color: var(--text-secondary); font-weight: 500; border-bottom: 1px solid var(--border-color); font-size: 0.875rem; }
        td { padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-primary); font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .badge-tcp { background-color: rgba(59, 130, 246, 0.1); color: var(--accent-primary); }
        .badge-udp { background-color: rgba(245, 158, 11, 0.1); color: #f59e0b; }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; padding: 16px; }
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
        <a href="/" class="nav-item">
            <i class="fa-solid fa-chart-line"></i>
            <span>Dashboard</span>
        </a>
        <a href="/connections" class="nav-item active">
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
        <a href="/logout" class="nav-item">
            <i class="fa-solid fa-sign-out-alt"></i>
            <span>Logout</span>
        </a>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="header">
            <div class="page-title">Active Connections</div>
            <button onclick="location.reload()" style="padding: 8px 16px; background-color: var(--accent-primary); color: white; border: none; border-radius: 6px; cursor: pointer;">Refresh</button>
        </div>
        
        <div class="table-container">
	    <style>
		.kill-btn {
		    background-color: #ef4444;
		    color: white;
		    border: none;
		    padding: 6px 12px;
		    border-radius: 6px;
		    cursor: pointer;
		    font-size: 0.8rem;
		}
		.kill-btn:hover {
		    background-color: #dc2626;
		}
	    </style>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Protocol</th>
                        <th>Proxy Name</th>
                        <th>Client</th>
                        <th>Start Time</th>
                        <th>Duration</th>
			<th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Connections}}
                    <tr>
                        <td style="font-family: monospace;">{{.ID}}</td>
                        <td><span class="badge {{if eq .Protocol "TCP"}}badge-tcp{{else}}badge-udp{{end}}">{{.Protocol}}</span></td>
                        <td>{{.Src}}</td>
                        <td>{{.Dst}}</td>
                        <td>{{.StartTime.Format "15:04:05"}}</td>
                        <td>{{since .StartTime}}</td>
			<td><button class="kill-btn" data-id="{{.ID}}">Kill</button></td>
                    </tr>
                    {{else}}
                    <tr>
                        <td colspan="6" style="text-align: center; color: var(--text-secondary);">No active connections</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    <script>
        document.addEventListener('click', function(e) {
            if (e.target && e.target.classList.contains('kill-btn')) {
                const connId = e.target.getAttribute('data-id');
                if (confirm('Are you sure you want to terminate connection ' + connId + '?')) {
                    fetch('/kill?id=' + connId, { method: 'POST' })
                        .then(response => {
                            if (response.ok) {
                                location.reload();
                            } else {
                                alert('Failed to kill connection.');
                            }
                        });
                }
            }
        });
    </script>
</body>
</html>
`

type ConnectionsPageData struct {
	Connections []*config.ActiveConnection
}

type ConnectionJSON struct {
	ID        string    `json:"id"`
	ProxyName string    `json:"proxy_name"`
	StartTime time.Time `json:"start_time"`
}

func ConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	connections := config.ListConnections()

	if r.URL.Query().Get("json") == "true" {
		var jsonConns []ConnectionJSON
		for _, c := range connections {
			jsonConns = append(jsonConns, ConnectionJSON{
				ID:        c.ID,
				ProxyName: c.ProxyName,
				StartTime: c.StartTime,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonConns)
		return
	}

	funcMap := template.FuncMap{
		"since": func(t time.Time) string {
			return time.Since(t).Round(time.Second).String()
		},
	}

	t, err := template.New("connections").Funcs(funcMap).Parse(connectionsTemplateHTML)
	if err != nil {
		logger.Error.Printf("Error parsing connections template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = t.Execute(w, ConnectionsPageData{Connections: connections})
	if err != nil {
		logger.Error.Printf("Error executing connections template: %v", err)
	}
}

func KillHandler(w http.ResponseWriter, r *http.Request) {
	connID := r.URL.Query().Get("id")
	if connID == "" {
		http.Error(w, "Missing connection ID", http.StatusBadRequest)
		return
	}

	conn, ok := config.ConnManager.Get(connID)
	if !ok {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	// Close the smux stream. This will cause the io.Copy loops to exit.
	if conn.Stream != nil {
		conn.Stream.Close()
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Connection terminated"))
	logger.Info.Printf("Web panel user terminated connection %s.", connID)
}
