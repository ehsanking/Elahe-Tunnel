package cmd

import (
	"fmt"
	"os"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/ehsanking/search-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the search tunnel client or server.",
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
	rootCmd.AddCommand(runCmd)
}
