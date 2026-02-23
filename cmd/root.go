package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "elahe-tunnel",
	Short: "Elahe Tunnel: A tool for creating secure tunnels over HTTP.",
	Long:  `Elahe Tunnel is a client/server application that allows you to tunnel TCP traffic over a masqueraded HTTP connection.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)
}
