package web

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
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

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	
	// Generate a self-signed cert in memory for the web panel
	certPEM, keyPEM, err := crypto.GenerateTLSConfig()
	if err != nil {
		logger.Error.Printf("Failed to generate TLS cert for web panel: %v", err)
		return
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logger.Error.Printf("Failed to parse TLS cert for web panel: %v", err)
		return
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	fmt.Printf("Web panel starting on https://%s\n", addr)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Error.Printf("Failed to start web panel: %v", err)
	}
}
