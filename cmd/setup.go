package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup [internal | external]",
	Short: "Initial setup for the Elahe Tunnel.",
	Long:  `Use 'setup' to configure the current machine as either an internal (relay) node inside a censored network or an external (exit) node with free internet access.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		setupType := args[0]
		switch setupType {
		case "internal":
			setupInternal()
		case "external":
			setupExternal()
		default:
			fmt.Printf("Error: Invalid setup type '%s'. Please use 'internal' or 'external'.\n", setupType)
			os.Exit(1)
		}
	},
}

func setupExternal() {
	fmt.Println("Setting up as an external (foreign) server...")

	// Generate connection key
	key, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("Error generating key:", err)
		os.Exit(1)
	}
	encodedKey := crypto.EncodeKeyToBase64(key)

	// Generate TLS certificate
	certPEM, keyPEM, err := crypto.GenerateTLSConfig()
	if err != nil {
		fmt.Println("Error generating TLS certificate:", err)
		os.Exit(1)
	}

	// Save TLS files
	if err := os.WriteFile("cert.pem", certPEM, 0644); err != nil {
		fmt.Println("Error saving cert.pem:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("key.pem", keyPEM, 0600); err != nil {
		fmt.Println("Error saving key.pem:", err)
		os.Exit(1)
	}

	// Save configuration
	cfg := &config.Config{
		NodeType:      "external",
		ConnectionKey: encodedKey,
	}
	if err := config.SaveConfig(cfg); err != nil {
		fmt.Println("Error saving configuration:", err)
		os.Exit(1)
	}

	fmt.Println("✅ External server setup complete.")
	fmt.Println("✅ TLS certificate and key saved to cert.pem and key.pem.")
	fmt.Println("\n🔑 Your connection key is:")
	fmt.Printf("\n    %s\n\n", encodedKey)
	fmt.Println("Save this key. You will need it to connect your internal server.")
}

func setupInternal() {
	fmt.Println("Setting up as an internal (Iran) server...")

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the IP address of your external server: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)

	fmt.Print("Enter the connection key: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)

	cfg := &config.Config{
		NodeType:      "internal",
		ConnectionKey: key,
		RemoteHost:    host,
	}

	fmt.Print("Do you want to enable the Web Panel? (y/N): ")
	enableWeb, _ := reader.ReadString('\n')
	enableWeb = strings.TrimSpace(strings.ToLower(enableWeb))

	if enableWeb == "y" || enableWeb == "yes" {
		cfg.WebPanelEnabled = true

		fmt.Print("Enter Web Panel Port (default 8080): ")
		portStr, _ := reader.ReadString('\n')
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			cfg.WebPanelPort = 8080
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Println("Invalid port, using default 8080")
				cfg.WebPanelPort = 8080
			} else {
				cfg.WebPanelPort = port
			}
		}

		fmt.Print("Enter Web Panel Username (default admin): ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)
		if user == "" {
			cfg.WebPanelUser = "admin"
		} else {
			cfg.WebPanelUser = user
		}

		fmt.Print("Enter Web Panel Password: ")
		pass, _ := reader.ReadString('\n')
		cfg.WebPanelPass = strings.TrimSpace(pass)
	}

	if err := config.SaveConfig(cfg); err != nil {
		fmt.Println("Error saving configuration:", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ Internal server setup complete. The tunnel will now attempt to connect.")
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
