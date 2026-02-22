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
	"encoding/json"
	"io"
	"net"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check the current status of the Elahe Tunnel.",
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

const socketPath = "/tmp/search-tunnel.sock"

func checkConnectionStatus(cfg *config.Config) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Println("  Status: Inactive (Tunnel process not running?)")
		return
	}
	defer conn.Close()

	// No need to send data, the server responds on connect
	jsonData, err := io.ReadAll(conn)
	if err != nil {
		fmt.Println("  Status: Error reading from tunnel process")
		return
	}

	var status struct {
		UdpEnabled         bool   `json:"udp_enabled"`
		UdpDestination     string `json:"udp_destination"`
		UdpPacketsIn       uint64 `json:"udp_packets_in"`
		UdpPacketsOut      uint64 `json:"udp_packets_out"`
		UdpBytesIn         uint64 `json:"udp_bytes_in"`
		UdpBytesOut        uint64 `json:"udp_bytes_out"`
		CurrentUdpPayloadSize uint64 `json:"current_udp_payload_size"`
	}

	if err := json.Unmarshal(jsonData, &status); err != nil {
		fmt.Println("  Status: Error parsing status response from tunnel")
		return
	}

	fmt.Println("  Status: Active")
	fmt.Println("  --- UDP Tunnel ---")
	if status.UdpEnabled {
		fmt.Printf("    Status: Enabled\n")
		fmt.Printf("    Destination: %s\n", status.UdpDestination)
		fmt.Printf("    Packets In/Out: %d / %d\n", status.UdpPacketsIn, status.UdpPacketsOut)
		fmt.Printf("    Bytes In/Out: %d / %d\n", status.UdpBytesIn, status.UdpBytesOut)
		fmt.Printf("    Current Payload Size: %d bytes\n", status.CurrentUdpPayloadSize)
	} else {
		fmt.Println("    Status: Disabled")
	}
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
