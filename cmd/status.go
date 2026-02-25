package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

const socketPath = "/tmp/elahe-tunnel.sock"
const pidFile = "/tmp/elahe-tunnel.pid"

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the current status of the Elahe Tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Check PID file first
		data, err := ioutil.ReadFile(pidFile)
		if err != nil {
			fmt.Println("Elahe Tunnel is NOT running (PID file not found).")
			return
		}

		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			fmt.Println("Elahe Tunnel is NOT running (invalid PID file).")
			os.Remove(pidFile)
			return
		}

		if !processExists(pid) {
			fmt.Println("Elahe Tunnel is NOT running (stale PID file).")
			fmt.Println("Check logs for errors: cat /tmp/elahe-tunnel.log")
			os.Remove(pidFile)
			return
		}

		fmt.Printf("Elahe Tunnel is RUNNING (PID %d).\n", pid)

		// 2. Try to get detailed stats via Unix socket (for Internal Node)
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			// This is expected on the External Node.
			fmt.Println("Detailed statistics are not available (this is normal for the external server).")
			return
		}
		defer conn.Close()

		fmt.Println("\n--- Detailed Statistics ---")
		statsData, err := io.ReadAll(conn)
		if err != nil {
			fmt.Printf("Error reading statistics: %v\n", err)
			return
		}

		var status interface{}
		if err := json.Unmarshal(statsData, &status); err != nil {
			fmt.Printf("Error parsing statistics: %v\n", err)
			return
		}

		prettyJSON, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			fmt.Printf("Error formatting statistics: %v\n", err)
			return
		}

		fmt.Println(string(prettyJSON))
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, Signal(0) is not supported. This code is for Linux/macOS.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
