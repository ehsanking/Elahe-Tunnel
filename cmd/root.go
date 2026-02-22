package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "search-tunnel",
	Short: "A censorship circumvention tool that tunnels traffic disguised as Google search packets.",
	Long:  `Search Tunnel is a CLI tool designed to bypass internet censorship by tunneling network traffic through packets that mimic Google search queries.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
