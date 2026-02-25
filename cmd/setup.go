package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup [internal | external]",
	Short: "Initial setup for the Elahe Tunnel.",
	Long:  `Use 'setup' to configure the current machine as either an internal (relay) node inside a censored network or an external (exit) node with free internet access.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var setupType string
		if len(args) > 0 {
			setupType = args[0]
		} else {
			// Interactive mode
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Please choose the node type:")
			fmt.Println("1. Internal (Relay Node - Inside Censored Network)")
			fmt.Println("2. External (Exit Node - Free Internet Access)")
			fmt.Print("Enter choice (1/2 or internal/external): ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			switch input {
			case "1", "internal":
				setupType = "internal"
			case "2", "external":
				setupType = "external"
			default:
				fmt.Printf("Error: Invalid choice '%s'. Please use '1' (internal) or '2' (external).\n", input)
				os.Exit(1)
			}
		}

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
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the port for the tunnel to listen on (default 443): ")
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	tunnelPort := 443
	if portStr != "" {
		tunnelPort, _ = strconv.Atoi(portStr)
	}

	// Check and free port
	checkAndFreePort(tunnelPort)

	// Check if config already exists
	if _, err := os.Stat(config.ConfigFileName); err == nil {
		fmt.Printf("\n⚠️  WARNING: A configuration file (%s) already exists!\n", config.ConfigFileName)
		fmt.Println("Running setup again will OVERWRITE the existing configuration and GENERATE A NEW KEY.")
		fmt.Println("Any clients using the old key will lose connection.")
		fmt.Print("\nAre you sure you want to continue? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input != "y" && input != "yes" {
			fmt.Println("Setup aborted.")
			os.Exit(0)
		}
	}

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
		TunnelPort:    tunnelPort,
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
	// Check if config already exists
	if _, err := os.Stat(config.ConfigFileName); err == nil {
		fmt.Printf("\n⚠️  WARNING: A configuration file (%s) already exists!\n", config.ConfigFileName)
		fmt.Println("Running setup again will OVERWRITE the existing configuration.")
		fmt.Print("\nAre you sure you want to continue? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input != "y" && input != "yes" {
			fmt.Println("Setup aborted.")
			os.Exit(0)
		}
	}

	fmt.Println("Setting up as an internal (Iran) server...")

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the IP address of your external server: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)

	fmt.Print("Enter the connection key: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)

	fmt.Print("Enter the port of your external server (default 443): ")
	pStr, _ := reader.ReadString('\n')
	pStr = strings.TrimSpace(pStr)
	tunnelPort := 443
	if pStr != "" {
		tunnelPort, _ = strconv.Atoi(pStr)
	}

	cfg := &config.Config{
		NodeType:      "internal",
		ConnectionKey: key,
		RemoteHost:    host,
		TunnelPort:    tunnelPort,
	}

	fmt.Print("Do you want to enable the Web Panel? (y/N): ")
	enableWeb, _ := reader.ReadString('\n')
	enableWeb = strings.TrimSpace(strings.ToLower(enableWeb))

	if enableWeb == "y" || enableWeb == "yes" {
		cfg.WebPanelEnabled = true

		fmt.Print("Enter Web Panel Port (default 3000): ")
		portStr, _ := reader.ReadString('\n')
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			cfg.WebPanelPort = 3000
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Println("Invalid port, using default 3000")
				cfg.WebPanelPort = 3000
			} else {
				cfg.WebPanelPort = port
			}
		}

		fmt.Print("Enter Web Panel Username (default: admin): ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)
		if user == "" {
			cfg.WebPanelUser = "admin"
		} else {
			cfg.WebPanelUser = user
		}

		for {
			fmt.Print("Enter Web Panel Password (min 8 chars, 1 uppercase, 1 number): ")
			pass, _ := reader.ReadString('\n')
			pass = strings.TrimSpace(pass)
			
			if len(pass) < 8 {
				fmt.Println("Password must be at least 8 characters long.")
				continue
			}
			
			hasUpper := false
			hasNumber := false
			for _, char := range pass {
				if char >= 'A' && char <= 'Z' {
					hasUpper = true
				}
				if char >= '0' && char <= '9' {
					hasNumber = true
				}
			}
			
			if !hasUpper || !hasNumber {
				fmt.Println("Password must contain at least one uppercase letter and one number.")
				continue
			}
			
			cfg.WebPanelPass = pass
			break
		}

		fmt.Print("Do you want to enable Two-Factor Authentication (2FA)? (y/N): ")
		enable2FA, _ := reader.ReadString('\n')
		enable2FA = strings.TrimSpace(strings.ToLower(enable2FA))

		if enable2FA == "y" || enable2FA == "yes" {
			secret, err := crypto.GenerateTOTPSecret()
			if err != nil {
				fmt.Printf("Failed to generate 2FA secret: %v\n", err)
			} else {
				cfg.WebPanel2FASecret = secret
				fmt.Println("\n========================================================")
				fmt.Println("✅ 2FA Enabled!")
				fmt.Printf("Your 2FA Secret Key is: %s\n", secret)
				fmt.Println("Please add this key to your Authenticator app (Google Authenticator, Authy, etc.).")
				fmt.Println("========================================================")
			}
		}
	}

	fmt.Print("Enter Local Port to listen on (e.g., 8080): ")
	localPortStr, _ := reader.ReadString('\n')
	localPortStr = strings.TrimSpace(localPortStr)
	if localPortStr != "" {
		p, _ := strconv.Atoi(localPortStr)
		cfg.LocalPort = p
	}

	fmt.Print("Enter Remote Destination (e.g., 127.0.0.1:80): ")
	destStr, _ := reader.ReadString('\n')
	destStr = strings.TrimSpace(destStr)
	if destStr != "" {
		cfg.DestinationHost = destStr
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

func checkAndFreePort(port int) {
	fmt.Printf("Checking port %d availability...\n", port)

	// Try to listen on port
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		ln.Close()
		fmt.Printf("✅ Port %d is free.\n", port)
		return
	}

	fmt.Printf("⚠️  Port %d is busy. Attempting to free it...\n", port)

	// Try to kill process using port
	cmd := exec.Command("fuser", "-k", fmt.Sprintf("%d/tcp", port))
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to kill process using fuser: %v. Trying lsof...\n", err)
		
		out, err := exec.Command("lsof", "-t", fmt.Sprintf("-i:%d", port)).Output()
		if err == nil && len(out) > 0 {
			pid := strings.TrimSpace(string(out))
			if pid != "" {
				exec.Command("kill", "-9", pid).Run()
			}
		}
	}

	// Wait a bit
	time.Sleep(2 * time.Second)

	// Check again
	ln, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		ln.Close()
		fmt.Printf("✅ Port %d has been freed.\n", port)
	} else {
		fmt.Printf("❌ Failed to free port %d. Please stop the service manually.\n", port)
		os.Exit(1)
	}
}
