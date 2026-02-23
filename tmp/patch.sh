#!/bin/bash

# This script is a temporary patch to be executed by the main install.sh

# --- HOTFIX: Add Web Panel Feature ---
echo -n "Applying web panel patches..."

# Create web panel file
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
	mux.HandleFunc("/", basicAuth(homeHandler, cfg.WebPanelUser, cfg.WebPanelPass, "Elahe Tunnel Panel"))

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	fmt.Printf("Web panel starting on http://%s\n", addr)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		fmt.Printf("Failed to start web panel: %v\n", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elahe Tunnel Status</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 40px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background-color: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 600px; width: 100%; text-align: center; }
        h1 { color: #1a73e8; }
        .status { margin-top: 20px; padding: 20px; background-color: #e8f5e9; border-left: 5px solid #4caf50; border-radius: 8px; }
        .status p { margin: 0; font-size: 1.2em; color: #2e7d32; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Elahe Tunnel Status</h1>
        <div class="status">
            <p>Server Connection: Active</p>
        </div>
    </div>
</body>
</html>
`)
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

# Patch config/config.go for Web Panel
if [ -f "internal/config/config.go" ]; then
    sed -i '/TunnelListenKey string `json:"tunnel_listen_key,omitempty"`/a \	WebPanelEnabled bool   `json:"web_panel_enabled,omitempty"`\n	WebPanelUser    string `json:"web_panel_user,omitempty"`\n	WebPanelPass    string `json:"web_panel_pass,omitempty"`\n	WebPanelPort    int    `json:"web_panel_port,omitempty"`' internal/config/config.go
fi

# Patch cmd/setup.go for Web Panel setup
if [ -f "cmd/setup.go" ]; then
    sed -i '/"strings"/a \	"strconv"' cmd/setup.go
    sed -i '/if err := config.SaveConfig(cfg); err != nil {/i \
	fmt.Print("Do you want to enable the Web Panel? (y/N): ")\n	enableWeb, _ := reader.ReadString('\''\n'\'')\n	enableWeb = strings.TrimSpace(strings.ToLower(enableWeb))\n\n	if enableWeb == "y" || enableWeb == "yes" {\n		cfg.WebPanelEnabled = true\n\n		fmt.Print("Enter Web Panel Port (default 8080): ")\n		portStr, _ := reader.ReadString('\''\n'\'')\n		portStr = strings.TrimSpace(portStr)\n		if portStr == "" {\n			cfg.WebPanelPort = 8080\n		} else {\n			port, err := strconv.Atoi(portStr)\n			if err != nil {\n				fmt.Println("Invalid port, using default 8080")\n				cfg.WebPanelPort = 8080\n			} else {\n				cfg.WebPanelPort = port\n			}\n		}\n\n		fmt.Print("Enter Web Panel Username (default admin): ")\n		user, _ := reader.ReadString('\''\n'\'')\n		user = strings.TrimSpace(user)\n		if user == "" {\n			cfg.WebPanelUser = "admin"\n		} else {\n			cfg.WebPanelUser = user\n		}\n\n		fmt.Print("Enter Web Panel Password: ")\n		pass, _ := reader.ReadString('\''\n'\'')\n		cfg.WebPanelPass = strings.TrimSpace(pass)\n	}' cmd/setup.go
fi

# Patch internal/tunnel/client.go to start Web Panel
if [ -f "internal/tunnel/client.go" ]; then
    sed -i '/"github.com\/ehsanking\/elahe-tunnel\/internal\/masquerade"/a \	"github.com/ehsanking/elahe-tunnel/internal/web"' internal/tunnel/client.go
    sed -i '/go runStatusServer(cfg)/a \	if cfg.WebPanelEnabled {\n		go web.StartServer(cfg)\n	}' internal/tunnel/client.go
fi

echo -e " ${GREEN}OK${NC}"
