package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/spf13/cobra"
)

// remoteCmd represents the remote command
var remoteCmd = &cobra.Command{
	Use:   "remote [ip:port]",
	Short: "Set the remote server address (for internal node)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		if cfg.NodeType != "internal" {
			fmt.Println("Error: This command is only for internal nodes.")
			return
		}

		parts := strings.Split(args[0], ":")
		host := parts[0]
		port := 443
		if len(parts) > 1 {
			p, err := strconv.Atoi(parts[1])
			if err == nil {
				port = p
			}
		}

		cfg.RemoteHost = host
		cfg.TunnelPort = port

		if err := config.SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}

		fmt.Printf("✅ Remote server updated to %s:%d\n", host, port)
		fmt.Println("Please restart the tunnel for changes to take effect.")
	},
}

// forwardCmd represents the forward command
var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Manage forwarding rules (like iptables)",
}

var forwardAddCmd = &cobra.Command{
	Use:   "add [local_port] [remote_port]",
	Short: "Add a forwarding rule",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}
		
		localPort, _ := strconv.Atoi(args[0])
		remotePort, _ := strconv.Atoi(args[1])

		// Check if rule exists
		for _, p := range cfg.Proxies {
			if p.LocalPort == localPort {
				fmt.Printf("Error: Rule for local port %d already exists.\n", localPort)
				return
			}
		}

		newProxy := config.ProxyConfig{
			Name:       fmt.Sprintf("rule-%d", localPort),
			Type:       "tcp",
			RemotePort: remotePort,
			LocalIP:    "127.0.0.1",
			LocalPort:  localPort,
		}
		cfg.Proxies = append(cfg.Proxies, newProxy)

		if err := config.SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}

		fmt.Printf("✅ Forwarding rule added: :%d -> :%d\n", localPort, remotePort)
	},
}

var forwardDelCmd = &cobra.Command{
	Use:   "del [local_port]",
	Short: "Delete a forwarding rule",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		localPort, _ := strconv.Atoi(args[0])

		found := false
		newProxies := []config.ProxyConfig{}
		for _, p := range cfg.Proxies {
			if p.LocalPort == localPort {
				found = true
				continue
			}
			newProxies = append(newProxies, p)
		}

		if !found {
			fmt.Printf("Error: No rule found for local port %d.\n", localPort)
			return
		}

		cfg.Proxies = newProxies
		if err := config.SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}

		fmt.Printf("✅ Forwarding rule deleted for port %d.\n", localPort)
	},
}

var forwardListCmd = &cobra.Command{
	Use:   "list",
	Short: "List forwarding rules",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		fmt.Println("Current Forwarding Rules:")
		fmt.Println("-------------------------")
		for _, p := range cfg.Proxies {
			fmt.Printf("Local :%d  ->  Remote :%d  (%s)\n", p.LocalPort, p.RemotePort, p.Name)
		}
		fmt.Println("-------------------------")
	},
}

func init() {
	rootCmd.AddCommand(remoteCmd)
	rootCmd.AddCommand(forwardCmd)
	forwardCmd.AddCommand(forwardAddCmd)
	forwardCmd.AddCommand(forwardDelCmd)
	forwardCmd.AddCommand(forwardListCmd)
}
