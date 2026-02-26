package web

import (
	"fmt"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
)

func StartServer(cfg *config.Config) {
	if !cfg.WebPanelEnabled {
		return
	}

	mux := http.NewServeMux()
	
	// Public routes
	mux.HandleFunc("/login", LoginHandler(cfg))
	mux.HandleFunc("/logout", LogoutHandler)

	// Protected routes
	mux.HandleFunc("/", AuthMiddleware(StatusHandler))
	mux.HandleFunc("/status", AuthMiddleware(JsonStatusHandler))
	mux.HandleFunc("/logs", AuthMiddleware(LogsHandler))
	mux.HandleFunc("/connections", AuthMiddleware(ConnectionsHandler))
	mux.HandleFunc("/kill", AuthMiddleware(KillHandler))

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	fmt.Printf("Web panel starting on http://%s\n", addr)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		logger.Error.Printf("Failed to start web panel: %v", err)
	}
}
