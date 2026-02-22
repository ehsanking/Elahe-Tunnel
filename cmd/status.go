package cmd

import (
	"fmt"
	"os"

	"github.com/ehsanking/search-tunnel/internal/config"
	"github.com/spf13/cobra"
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
		}
		fmt.Println("  Status: Inactive (Live check not implemented yet)")
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
