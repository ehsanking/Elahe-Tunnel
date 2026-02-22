package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "elahe-tunnel",
	Short: "Elahe Tunnel: A tool for creating secure tunnels over HTTP.",
	Long: `
______ _           _   _ 
|  ___| |         | | | |
| |_  | | __ _ ___| |_| | __ _ _ __   __ _ 
|  _| | |/ _` / __| __| |/ _` | '_ \ / _` |
| |   | | (_| \__ \ |_| | (_| | | | | (_| |
\_|   |_|\__,_|___/\__|_|\__,_|_| |_|\__,_|

Elahe Tunnel is a client/server application that allows you to tunnel TCP traffic over a masqueraded HTTP connection.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
