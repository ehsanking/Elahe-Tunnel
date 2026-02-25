package web

import (
	"bufio"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ehsanking/elahe-tunnel/internal/logger"
)

const logsTemplateHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Logs - Elahe Tunnel</title>
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
            --accent-danger: #ef4444;
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
        .main-content { flex: 1; margin-left: 260px; padding: 32px; overflow-y: auto; height: 100vh; display: flex; flex-direction: column; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .page-title { font-size: 1.8rem; font-weight: 600; }

        /* Logs Container */
        .logs-container { flex: 1; background-color: #000; border-radius: 8px; border: 1px solid var(--border-color); padding: 16px; overflow-y: auto; font-family: 'Courier New', Courier, monospace; font-size: 0.9rem; line-height: 1.5; white-space: pre-wrap; }
        .log-entry { margin-bottom: 4px; }
        .log-info { color: #10b981; }
        .log-error { color: #ef4444; }
        .log-timestamp { color: #64748b; margin-right: 8px; }

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
        <a href="/connections" class="nav-item">
            <i class="fa-solid fa-network-wired"></i>
            <span>Connections</span>
        </a>
        <a href="/logs" class="nav-item active">
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
            <div class="page-title">System Logs</div>
            <button onclick="location.reload()" style="padding: 8px 16px; background-color: var(--accent-primary); color: white; border: none; border-radius: 6px; cursor: pointer;">Refresh</button>
        </div>
        
        <div class="logs-container" id="logs-output">
            {{range .Logs}}
            <div class="log-entry">
                {{if .IsError}}<span class="log-error">[ERROR]</span>{{else}}<span class="log-info">[INFO]</span>{{end}}
                <span class="log-content">{{.Content}}</span>
            </div>
            {{end}}
        </div>
    </div>

    <script>
        // Auto-scroll to bottom
        const logsContainer = document.getElementById('logs-output');
        logsContainer.scrollTop = logsContainer.scrollHeight;
    </script>
</body>
</html>
`

type LogEntry struct {
	IsError bool
	Content string
}

type LogsPageData struct {
	Logs []LogEntry
}

func LogsHandler(w http.ResponseWriter, r *http.Request) {
	logFilePath := filepath.Join("logs", "elahe-tunnel.log")
	file, err := os.Open(logFilePath)
	if err != nil {
		logger.Error.Printf("Failed to open log file: %v", err)
		http.Error(w, "Failed to read logs", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(file)
	
	// Read last 1000 lines (simplified: read all then slice)
	// For production with huge logs, we should read from end using Seek
	var allLines []string
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	start := 0
	if len(allLines) > 1000 {
		start = len(allLines) - 1000
	}

	for _, line := range allLines[start:] {
		isError := strings.Contains(line, "ERROR:")
		logs = append(logs, LogEntry{
			IsError: isError,
			Content: line,
		})
	}

	t, err := template.New("logs").Parse(logsTemplateHTML)
	if err != nil {
		logger.Error.Printf("Error parsing logs template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = t.Execute(w, LogsPageData{Logs: logs})
	if err != nil {
		logger.Error.Printf("Error executing logs template: %v", err)
	}
}
