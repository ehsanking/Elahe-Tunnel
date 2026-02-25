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
	
	// Public routes
	mux.HandleFunc("/login", LoginHandler(cfg))
	mux.HandleFunc("/logout", LogoutHandler)

	// Protected routes
	mux.HandleFunc("/", AuthMiddleware(StatusHandler))
	mux.HandleFunc("/status", AuthMiddleware(JsonStatusHandler))

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	fmt.Printf("Web panel starting on http://%s\n", addr)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		fmt.Printf("Failed to start web panel: %v\n", err)
	}
}
