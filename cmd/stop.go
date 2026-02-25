package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

const pidFile = "/tmp/elahe-tunnel.pid"

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running Elahe Tunnel background process.",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := ioutil.ReadFile(pidFile)
		if err != nil {
			fmt.Println("Elahe Tunnel is not running (PID file not found).")
			return
		}

		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			fmt.Printf("Invalid PID file: %v\n", err)
			os.Remove(pidFile)
			return
		}

		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("Failed to find process %d: %v\n", pid, err)
			os.Remove(pidFile)
			return
		}

		// Send SIGTERM
		fmt.Printf("Stopping Elahe Tunnel (PID %d)...\n", pid)
		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			fmt.Printf("Failed to stop process: %v\n", err)
		} else {
			fmt.Println("Stop signal sent successfully.")
		}

		// Clean up PID file
		os.Remove(pidFile)
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
