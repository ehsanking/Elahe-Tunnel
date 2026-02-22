package cmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/crypto"
	"github.com/ehsanking/search-tunnel/internal/masquerade"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check the current status of the tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Checking tunnel status...")
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("Configuration not found. Please run 'setup' first.")
			os.Exit(1)
		}

		fmt.Printf("  Node Type: %s\n", cfg.NodeType)
		if cfg.NodeType == "internal" {
			fmt.Printf("  Remote Host: %s\n", cfg.RemoteHost)
			checkConnectionStatus(cfg)
		} else {
			fmt.Println("  Status: Listening (External node)")
		}
	},
}

func checkConnectionStatus(cfg *config.Config) {
	key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
	if err != nil {
		fmt.Println("  Status: Inactive (Invalid Key)")
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	pingData, _ := crypto.Encrypt([]byte("SEARCH_TUNNEL_PING"), key)
	req, _ := masquerade.WrapInHttpRequest(pingData, "www.google.com")
	req.URL.Scheme = "https"
	req.URL.Host = cfg.RemoteHost
	req.URL.Path = "/favicon.ico"

	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("  Status: Inactive (Connection Error)")
		return
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	encryptedPong, err := masquerade.UnwrapFromHttpResponse(resp)
	if err != nil {
		fmt.Println("  Status: Inactive (Invalid Response)")
		return
	}

	pong, err := crypto.Decrypt(encryptedPong, key)
	if err != nil || string(pong) != "SEARCH_TUNNEL_PONG" {
		fmt.Println("  Status: Inactive (Authentication Failed)")
		return
	}

	fmt.Printf("  Status: Active\n")
	fmt.Printf("  Latency: %s\n", latency.Round(time.Millisecond))
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
