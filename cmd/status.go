package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/spf13/cobra"
)

const socketPath = "/tmp/elahe-tunnel.sock"

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the current status of the Elahe Tunnel client.",
	Run: func(cmd *cobra.Command, args []string) {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting to status socket: %v\n", err)
			fmt.Fprintln(os.Stderr, "Is the Elahe Tunnel client running?")
			os.Exit(1)
		}
		defer conn.Close()

		data, err := io.ReadAll(conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from status socket: %v\n", err)
			os.Exit(1)
		}

		var status interface{}
		if err := json.Unmarshal(data, &status); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing status data: %v\n", err)
			os.Exit(1)
		}

		prettyJSON, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting status data: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(prettyJSON))
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
