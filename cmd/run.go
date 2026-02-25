package cmd

import (
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"fmt"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Elahe Tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		// Override config with flags if they are set
		if cmd.Flags().Changed("remote-host") {
			cfg.RemoteHost, _ = cmd.Flags().GetString("remote-host")
		}
		if cmd.Flags().Changed("web-panel-port") {
			cfg.WebPanelPort, _ = cmd.Flags().GetInt("web-panel-port")
		}
		if cmd.Flags().Changed("dns-proxy-enabled") {
			cfg.DnsProxyEnabled, _ = cmd.Flags().GetBool("dns-proxy-enabled")
		}

		switch cfg.NodeType {
		case "internal":
			if err := tunnel.RunClient(cfg); err != nil {
				fmt.Printf("Client error: %v\n", err)
			}
		case "external":
			key, err := crypto.DecodeBase64Key(cfg.ConnectionKey)
			if err != nil {
				fmt.Printf("Error decoding key: %v\n", err)
				return
			}
			if err := tunnel.RunServer(key); err != nil {
				fmt.Printf("Server error: %v\n", err)
			}
		default:
			fmt.Printf("Error: Invalid node type '%s'. Please run setup first.\n", cfg.NodeType)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Add flags for overriding config values
	runCmd.Flags().String("remote-host", "", "Override the remote host IP or domain")
	runCmd.Flags().Int("web-panel-port", 0, "Override the web panel port")
	runCmd.Flags().Bool("dns-proxy-enabled", false, "Override the DNS proxy setting")
}
