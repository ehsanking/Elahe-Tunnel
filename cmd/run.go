package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Elahe Tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		foreground, _ := cmd.Flags().GetBool("foreground")

		if !foreground && os.Getenv("ELAHE_DAEMON") != "1" {
			// Check if already running
			if _, err := os.Stat(pidFile); err == nil {
				data, _ := ioutil.ReadFile(pidFile)
				pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
				if processExists(pid) {
					fmt.Printf("Elahe Tunnel is already running (PID %d). Use 'elahe-tunnel stop' to stop it.\n", pid)
					return
				}
			}

			// Start in background
			executable, _ := os.Executable()
			newArgs := append(os.Args[1:], "--foreground")
			daemonCmd := exec.Command(executable, newArgs...)
			daemonCmd.Env = append(os.Environ(), "ELAHE_DAEMON=1")
			
			// Redirect output to a log file or /dev/null
			logFile, err := os.OpenFile("/tmp/elahe-tunnel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err == nil {
				daemonCmd.Stdout = logFile
				daemonCmd.Stderr = logFile
			}

			err = daemonCmd.Start()
			if err != nil {
				fmt.Printf("Failed to start in background: %v\n", err)
				return
			}

			// Write PID file
			ioutil.WriteFile(pidFile, []byte(strconv.Itoa(daemonCmd.Process.Pid)), 0644)
			fmt.Printf("Elahe Tunnel started in background (PID %d).\n", daemonCmd.Process.Pid)
			fmt.Println("Logs are available at /tmp/elahe-tunnel.log")
			return
		}

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
			if err := tunnel.RunServer(cfg); err != nil {
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
	runCmd.Flags().Bool("foreground", false, "Run in foreground (do not daemonize)")
}

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
