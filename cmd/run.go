package cmd

import (
	"fmt"
	"os"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var dnsProxyEnabled bool
var destinationHost string
var udpProxyEnabled bool
var destinationUdpHost string
var tunnelListenAddr string
var tunnelListenKey string

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Elahe Tunnel client or server.",
	Long:  `This command starts the tunnel. It automatically detects whether to run as an internal (client) or external (server) node based on the existing configuration.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("Error loading configuration. Please run 'setup' first.", err)
			os.Exit(1)
		}

		switch cfg.NodeType {
		case "internal":
			fmt.Println("Starting tunnel in internal (client) mode...")
			cfg.DnsProxyEnabled = dnsProxyEnabled
			cfg.DestinationHost = destinationHost
			cfg.UdpProxyEnabled = udpProxyEnabled
			cfg.DestinationUdpHost = destinationUdpHost
			cfg.TunnelListenAddr = tunnelListenAddr
			cfg.TunnelListenKey = tunnelListenKey
			if err := tunnel.RunClient(cfg); err != nil {
				fmt.Println("Client error:", err)
				os.Exit(1)
			}
		case "external":
			fmt.Println("Starting tunnel in external (server) mode...")
			if err := tunnel.RunServer(cfg); err != nil {
				fmt.Println("Server error:", err)
				os.Exit(1)
			}
		default:
			fmt.Printf("Unknown node type '%s' in configuration.\n", cfg.NodeType)
			os.Exit(1)
		}
	},
}

func init() {
	runCmd.Flags().BoolVar(&dnsProxyEnabled, "dns", false, "Enable the local DNS proxy to tunnel DNS queries")
	runCmd.Flags().StringVar(&destinationHost, "dest", "tcpbin.com:4242", "The destination host and port to tunnel to")
	runCmd.Flags().BoolVar(&udpProxyEnabled, "udp", false, "Enable the local UDP proxy to tunnel UDP packets")
	runCmd.Flags().StringVar(&destinationUdpHost, "dest-udp", "8.8.8.8:53", "The destination UDP host and port to tunnel to")
	runCmd.Flags().StringVar(&tunnelListenAddr, "listen-tunnel-addr", "", "(Proxy mode) Address to listen for incoming tunnel connections")
	runCmd.Flags().StringVar(&tunnelListenKey, "listen-tunnel-key", "", "(Proxy mode) Connection key for incoming tunnel connections")
	rootCmd.AddCommand(runCmd)
}
