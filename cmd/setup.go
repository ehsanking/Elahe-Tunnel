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

// ANSI Colors
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

var setupCmd = &cobra.Command{
	Use:   "setup [internal | external]",
	Short: "Simple setup for Elahe Tunnel",
	Long:  `Quickly configure your server as an Internal (Iran) or External (Foreign) node.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrintBanner()

		var setupType string
		if len(args) > 0 {
			setupType = args[0]
		} else {
			setupType = askNodeType()
		}

		switch setupType {
		case "internal":
			setupInternal()
		case "external":
			setupExternal()
		default:
			fmt.Printf("%sError: Invalid setup type '%s'. Use 'internal' or 'external'.%s\n", ColorRed, setupType, ColorReset)
			os.Exit(1)
		}
	},
}

func PrintBanner() {
	fmt.Println(ColorCyan + "=========================================" + ColorReset)
	fmt.Println(ColorCyan + "   Elahe Tunnel - Simple Setup Wizard    " + ColorReset)
	fmt.Println(ColorCyan + "=========================================" + ColorReset)
	fmt.Println()
}

func askNodeType() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(ColorYellow + "Choose your server type:" + ColorReset)
	fmt.Println("1. " + ColorGreen + "External" + ColorReset + " (Foreign Server - Exit Node)")
	fmt.Println("2. " + ColorBlue + "Internal" + ColorReset + " (Iran Server - Relay Node)")
	fmt.Print("\nEnter choice (1/2): ")
	
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "1" || strings.ToLower(input) == "external" {
		return "external"
	} else if input == "2" || strings.ToLower(input) == "internal" {
		return "internal"
	}
	
	fmt.Println(ColorRed + "Invalid choice. Defaulting to External." + ColorReset)
	return "external"
}

func setupExternal() {
	fmt.Println("\n" + ColorGreen + "--- External Server Setup ---" + ColorReset)
	
	// Port selection
	port := 443
	fmt.Printf("Enter Tunnel Port (default %d): ", port)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		p, err := strconv.Atoi(input)
		if err == nil {
			port = p
		}
	}

	checkAndFreePort(port)

	// Generate Key
	key, _ := crypto.GenerateKey()
	encodedKey := crypto.EncodeKeyToBase64(key)

	// Generate Certs
	certPEM, keyPEM, _ := crypto.GenerateTLSConfig()
	os.WriteFile("cert.pem", certPEM, 0644)
	os.WriteFile("key.pem", keyPEM, 0600)

	// Save Config
	cfg := &config.Config{
		NodeType:      "external",
		ConnectionKey: encodedKey,
		TunnelPort:    port,
	}
	config.SaveConfig(cfg)

	fmt.Println("\n" + ColorGreen + "✅ Setup Complete!" + ColorReset)
	fmt.Println(ColorYellow + "--------------------------------------------------" + ColorReset)
	fmt.Println("Use this KEY on your Internal server:")
	fmt.Printf("\n" + ColorCyan + "%s" + ColorReset + "\n\n", encodedKey)
	fmt.Println(ColorYellow + "--------------------------------------------------" + ColorReset)
	
	// Auto-start suggestion
	fmt.Println("Starting server now...")
	runServer()
}

func setupInternal() {
	fmt.Println("\n" + ColorBlue + "--- Internal Server Setup ---" + ColorReset)
	reader := bufio.NewReader(os.Stdin)

	// External IP
	fmt.Print("Enter External Server IP: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		fmt.Println(ColorRed + "IP is required!" + ColorReset)
		os.Exit(1)
	}

	// Connection Key
	fmt.Print("Enter Connection Key (leave empty for default): ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)

	// Port
	port := 443
	fmt.Printf("Enter External Server Port (default %d): ", port)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		p, err := strconv.Atoi(input)
		if err == nil {
			port = p
		}
	}

	// Simple Forwarding Rule
	fmt.Println("\n" + ColorYellow + "Configure Forwarding (Traffic from Iran -> Foreign)" + ColorReset)
	
	localPort := 8080
	fmt.Printf("Local Port to Listen on (default %d): ", localPort)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		p, err := strconv.Atoi(input)
		if err == nil {
			localPort = p
		}
	}

	remotePort := 80
	fmt.Printf("Remote Port to Forward to (default %d): ", remotePort)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		p, err := strconv.Atoi(input)
		if err == nil {
			remotePort = p
		}
	}

	cfg := &config.Config{
		NodeType:      "internal",
		ConnectionKey: key,
		RemoteHost:    host,
		TunnelPort:    port,
		Proxies: []config.ProxyConfig{
			{
				Name:       "default-rule",
				Type:       "tcp",
				RemotePort: remotePort,
				LocalIP:    "0.0.0.0",
				LocalPort:  localPort,
			},
		},
	}
	config.SaveConfig(cfg)

	fmt.Println("\n" + ColorGreen + "✅ Setup Complete!" + ColorReset)
	fmt.Printf("Traffic on port %d will be forwarded to remote port %d\n", localPort, remotePort)
	
	fmt.Println("Starting client now...")
	runClient()
}

func checkAndFreePort(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		ln.Close()
		return
	}
	
	fmt.Printf(ColorYellow + "Port %d is busy. Freeing it...\n" + ColorReset, port)
	exec.Command("fuser", "-k", fmt.Sprintf("%d/tcp", port)).Run()
	time.Sleep(1 * time.Second)
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

// Helpers to run immediately
func runServer() {
	cmd := exec.Command(os.Args[0], "run")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func runClient() {
	cmd := exec.Command(os.Args[0], "run")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
