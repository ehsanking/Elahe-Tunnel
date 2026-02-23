#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Spinner Function ---
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Elahe Tunnel Single-Line Installer v3.2 (Final) ${NC}"
echo -e "${GREEN}=========================================${NC}"

# 1. Install Dependencies
apt-get update -qq && apt-get install -y -qq unzip curl file &> /dev/null

# 2. Download Source Code
echo -n "Downloading Elahe Tunnel source code..."
(
    rm -rf Elahe-Tunnel-main elahe-tunnel-main main.zip
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip" || \
    curl -s -L --connect-timeout 15 --max-time 300 -o main.zip "https://mirror.ghproxy.com/https://github.com/ehsanking/Elahe-Tunnel/archive/refs/heads/main.zip"
    unzip -o -q main.zip
) &> /dev/null &
spinner $!
wait $!

if [ -d "Elahe-Tunnel-main" ]; then
    SOURCE_DIR="Elahe-Tunnel-main"
elif [ -d "elahe-tunnel-main" ]; then
    SOURCE_DIR="elahe-tunnel-main"
else
    echo -e "\n${RED}Failed to download source code.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 3. Install Go
if ! command -v go &> /dev/null || [ "$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2)" -lt 24 ]; then
    echo -n "Installing Go 1.24.0..."
    (
        rm -rf /usr/local/go
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        URL="https://go.dev/dl/go1.24.0.linux-${ARCH}.tar.gz"
        curl -L -o /tmp/go.tar.gz "$URL"
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    ) &> /dev/null &
    spinner $!
    wait $!
    echo -e " ${GREEN}OK${NC}"
fi
export PATH=/usr/local/go/bin:$PATH

# 4. Overwrite source files and Compile
echo -n "Applying patches and compiling..."
cd "$SOURCE_DIR"

# --- Create/Overwrite All Corrected Files ---

mkdir -p internal/stats
cat <<'EOF' > internal/stats/stats.go
package stats

import (
	"sync/atomic"
	"time"
)

var (
	tcpActiveConnections int64
	tcpBytesIn           uint64
	tcpBytesOut          uint64
	udpBytesIn           uint64
	udpBytesOut          uint64
	lastSuccessfulPing   int64
)

func AddTcpActiveConnection()    { atomic.AddInt64(&tcpActiveConnections, 1) }
func RemoveTcpActiveConnection() { atomic.AddInt64(&tcpActiveConnections, -1) }
func GetTcpActiveConnections() int64 { return atomic.LoadInt64(&tcpActiveConnections) }
func AddTcpBytesIn(n uint64)     { atomic.AddUint64(&tcpBytesIn, n) }
func AddTcpBytesOut(n uint64)    { atomic.AddUint64(&tcpBytesOut, n) }
func GetTcpBytesIn() uint64      { return atomic.LoadUint64(&tcpBytesIn) }
func GetTcpBytesOut() uint64     { return atomic.LoadUint64(&tcpBytesOut) }
func AddUdpBytesIn(n uint64)     { atomic.AddUint64(&udpBytesIn, n) }
func AddUdpBytesOut(n uint64)    { atomic.AddUint64(&udpBytesOut, n) }
func GetUdpBytesIn() uint64      { return atomic.LoadUint64(&udpBytesIn) }
func GetUdpBytesOut() uint64     { return atomic.LoadUint64(&udpBytesOut) }
func SetLastSuccessfulPing(t int64) { atomic.StoreInt64(&lastSuccessfulPing, t) }
func GetLastSuccessfulPing() int64  { return atomic.LoadInt64(&lastSuccessfulPing) }

type Status struct {
	TcpActiveConnections int64  `json:"TcpActiveConnections"`
	TcpBytesIn           uint64 `json:"TcpBytesIn"`
	TcpBytesOut          uint64 `json:"TcpBytesOut"`
	UdpBytesIn           uint64 `json:"UdpBytesIn"`
	UdpBytesOut          uint64 `json:"UdpBytesOut"`
	LastSuccessfulPing   int64  `json:"LastSuccessfulPing"`
	ConnectionHealth     string `json:"ConnectionHealth"`
}

func GetStatus() Status {
	status := Status{
		TcpActiveConnections: GetTcpActiveConnections(),
		TcpBytesIn:           GetTcpBytesIn(),
		TcpBytesOut:          GetTcpBytesOut(),
		UdpBytesIn:           GetUdpBytesIn(),
		UdpBytesOut:          GetUdpBytesOut(),
		LastSuccessfulPing:   GetLastSuccessfulPing(),
	}

	if time.Now().Unix()-status.LastSuccessfulPing < 90 {
		status.ConnectionHealth = "Connected"
	} else {
		status.ConnectionHealth = "Disconnected"
	}
	return status
}
EOF

mkdir -p internal/web
cat <<'EOF' > internal/web/server.go
package web

import (
	"fmt"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/config"
)

func StartServer(cfg *config.Config) {
	if !cfg.WebPanelEnabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", basicAuth(StatusHandler, cfg.WebPanelUser, cfg.WebPanelPass, "Elahe Tunnel Panel"))

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.WebPanelPort)
	fmt.Printf("Web panel starting on http://%s\n", addr)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		fmt.Printf("Failed to start web panel: %v\n", err)
	}
}

func basicAuth(handler http.HandlerFunc, username, password, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized.\n"))
			return
		}

		handler(w, r)
	}
}
EOF

cat <<'EOF' > internal/web/status.go
package web

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

const statusTemplateHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elahe Tunnel Status</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 40px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }
        .container { background-color: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); max-width: 800px; width: 100%; }
        h1 { color: #1a73e8; text-align: center; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .card { background-color: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 5px solid #1a73e8; }
        .card h2 { margin-top: 0; font-size: 1.2em; color: #333; }
        .card p { margin: 10px 0 0; font-size: 1em; color: #5f6368; }
		.card p span { font-size: 1.6em; font-weight: 600; color: #1a73e8; display: block; margin-top: 4px;}
		.rate { font-size: 0.8em !important; color: #5f6368 !important; font-weight: normal !important; }
        .health { text-align: center; margin-top: 30px; padding: 15px; border-radius: 8px; font-size: 1.2em; font-weight: 600;}
        .health.ok { background-color: #e8f5e9; color: #2e7d32; border-left: 5px solid #4caf50; }
        .health.fail { background-color: #ffebee; color: #c62828; border-left: 5px solid #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Elahe Tunnel Status</h1>
		<div id="health-status" class="health">
			Checking connection...
        </div>
        <div class="grid">
            <div class="card">
                <h2>TCP</h2>
				<p>Active Connections: <span id="tcp-active">0</span></p>
				<p>Data In: <span id="tcp-in">0 B</span> <span id="tcp-in-rate" class="rate"></span></p>
				<p>Data Out: <span id="tcp-out">0 B</span> <span id="tcp-out-rate" class="rate"></span></p>
            </div>
            <div class="card">
                <h2>UDP</h2>
				<p>Active Connections: <span id="udp-active">N/A</span></p> 
                <p>Data In: <span id="udp-in">0 B</span> <span id="udp-in-rate" class="rate"></span></p>
                <p>Data Out: <span id="udp-out">0 B</span> <span id="udp-out-rate" class="rate"></span></p>
            </div>
        </div>
    </div>

	<script>
		let lastStats = null;
		const fetchInterval = 5000; // 5 seconds

		function formatBytes(bytes, decimals = 2) {
			if (bytes === 0) return '0 B';
			const k = 1024;
			const dm = decimals < 0 ? 0 : decimals;
			const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
		}

		function updateStats() {
			fetch('/status?json=true')
				.then(response => response.json())
				.then(data => {
					const healthDiv = document.getElementById('health-status');
					healthDiv.textContent = data.ConnectionHealth;
					healthDiv.className = 'health ' + (data.ConnectionHealth === 'Connected' ? 'ok' : 'fail');

					document.getElementById('tcp-active').textContent = data.TcpActiveConnections;
					
					document.getElementById('tcp-in').textContent = formatBytes(data.TcpBytesIn);
					document.getElementById('tcp-out').textContent = formatBytes(data.TcpBytesOut);
					document.getElementById('udp-in').textContent = formatBytes(data.UdpBytesIn);
					document.getElementById('udp-out').textContent = formatBytes(data.UdpBytesOut);

					if (lastStats) {
						const intervalSeconds = fetchInterval / 1000;
						document.getElementById('tcp-in-rate').textContent = '(' + formatBytes((data.TcpBytesIn - lastStats.TcpBytesIn) / intervalSeconds) + '/s)';
						document.getElementById('tcp-out-rate').textContent = '(' + formatBytes((data.TcpBytesOut - lastStats.TcpBytesOut) / intervalSeconds) + '/s)';
						document.getElementById('udp-in-rate').textContent = '(' + formatBytes((data.UdpBytesIn - lastStats.UdpBytesIn) / intervalSeconds) + '/s)';
						document.getElementById('udp-out-rate').textContent = '(' + formatBytes((data.UdpBytesOut - lastStats.UdpBytesOut) / intervalSeconds) + '/s)';
					}
					lastStats = data;
				})
				.catch(error => {
					console.error('Error fetching stats:', error);
					const healthDiv = document.getElementById('health-status');
					healthDiv.textContent = 'Error fetching status';
					healthDiv.className = 'health fail';
				});
		}

		document.addEventListener('DOMContentLoaded', () => {
			updateStats();
			setInterval(updateStats, fetchInterval);
		});
	</script>
</body>
</html>
`

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("json") == "true" {
		status := stats.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
		return
	}

	t, err := template.New("status").Parse(statusTemplateHTML)
	if err != nil {
		log.Printf("Error parsing status template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = t.Execute(w, nil) // No data needed for the initial template
	if err != nil {
		log.Printf("Error executing status template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
EOF

cat <<'EOF' > internal/config/config.go
package config

import (
	"encoding/json"
	"os"
)

const ConfigFileName = "search_tunnel_config.json"

type Config struct {
	NodeType           string `json:"node_type"`
	ConnectionKey      string `json:"connection_key"`
	RemoteHost         string `json:"remote_host,omitempty"`
	DnsProxyEnabled    bool   `json:"dns_proxy_enabled,omitempty"`
	DestinationHost    string `json:"destination_host,omitempty"`
	UdpProxyEnabled    bool   `json:"udp_proxy_enabled,omitempty"`
	DestinationUdpHost string `json:"destination_udp_host,omitempty"`
	TunnelListenAddr   string `json:"tunnel_listen_addr,omitempty"`
	TunnelListenKey    string `json:"tunnel_listen_key,omitempty"`
	WebPanelEnabled    bool   `json:"web_panel_enabled,omitempty"`
	WebPanelUser       string `json:"web_panel_user,omitempty"`
	WebPanelPass       string `json:"web_panel_pass,omitempty"`
	WebPanelPort       int    `json:"web_panel_port,omitempty"`
}

func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFileName, data, 0600)
}

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
EOF

cat <<'EOF' > cmd/setup.go
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
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		setupType := args[0]
		switch setupType {
		case "internal":
			setupInternal()
		case "external":
			setupExternal()
		default:
			fmt.Printf("Error: Invalid setup type '%s'.\n", setupType)
			os.Exit(1)
		}
	},
}

func setupExternal() {
	fmt.Println("Setting up as an external server...")
	key, _ := crypto.GenerateKey()
	encodedKey := crypto.EncodeKeyToBase64(key)
	certPEM, keyPEM, _ := crypto.GenerateTLSConfig()
	os.WriteFile("cert.pem", certPEM, 0644)
	os.WriteFile("key.pem", keyPEM, 0600)

	cfg := &config.Config{
		NodeType:      "external",
		ConnectionKey: encodedKey,
	}
	config.SaveConfig(cfg)

	fmt.Println("✅ External server setup complete.")
	fmt.Printf("\n🔑 Your connection key is:\n\n    %s\n\n", encodedKey)
}

func setupInternal() {
	fmt.Println("Setting up as an internal server...")
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the IP of your external server: ")
	host, _ := reader.ReadString('\n')

	fmt.Print("Enter the connection key: ")
	key, _ := reader.ReadString('\n')

	cfg := &config.Config{
		NodeType:      "internal",
		ConnectionKey: strings.TrimSpace(key),
		RemoteHost:    strings.TrimSpace(host),
	}

	fmt.Print("Enable Web Panel? (y/N): ")
	enableWeb, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(enableWeb)) == "y" {
		cfg.WebPanelEnabled = true
		fmt.Print("Enter Web Panel Port (default 8080): ")
		portStr, _ := reader.ReadString('\n')
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			cfg.WebPanelPort = 8080
		} else {
			cfg.WebPanelPort = port
		}

		fmt.Print("Enter Web Panel Username (default admin): ")
		user, _ := reader.ReadString('\n')
		cfg.WebPanelUser = strings.TrimSpace(user)
		if cfg.WebPanelUser == "" {
			cfg.WebPanelUser = "admin"
		}

		fmt.Print("Enter Web Panel Password: ")
		pass, _ := reader.ReadString('\n')
		cfg.WebPanelPass = strings.TrimSpace(pass)
	}

	config.SaveConfig(cfg)
	fmt.Println("\n✅ Internal server setup complete.")
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
EOF

cat <<'EOF' > cmd/run.go
package cmd

import (
	"fmt"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/tunnel"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Elahe Tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
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
			tunnel.RunClient(cfg)
		case "external":
			key, _ := crypto.DecodeBase64Key(cfg.ConnectionKey)
			tunnel.RunServer(key)
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
}
EOF

cat <<'EOF' > cmd/root.go
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
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(runCmd)
}
EOF

mkdir -p internal/tunnel

cat <<'EOF' > internal/tunnel/ping.go
package tunnel

import (
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
)

func handlePingRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, err := masquerade.UnwrapFromHttpRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		decrypted, err := crypto.Decrypt(encrypted, key)
		if err != nil || string(decrypted) != "ping" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		stats.SetLastSuccessfulPing(time.Now().Unix())

		encryptedResp, _ := crypto.Encrypt([]byte("pong"), key)
		masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
	}
}
EOF

cat <<'EOF' > internal/tunnel/client.go
package tunnel

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/config"
	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/ehsanking/elahe-tunnel/internal/web"
)

func RunClient(cfg *config.Config) error {
	if cfg.WebPanelEnabled {
		go web.StartServer(cfg)
	}

	key, _ := crypto.DecodeBase64Key(cfg.ConnectionKey)

	netDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         netDialer.DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	httpClient := &http.Client{Transport: tr}

	go manageConnection(httpClient, cfg, key)

	localListener, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		return fmt.Errorf("failed to listen on local port: %v", err)
	}
	defer localListener.Close()

	logger.Info.Println("SOCKS5 proxy listening on 127.0.0.1:1080")

	for {
		localConn, err := localListener.Accept()
		if err != nil {
			continue
		}
		stats.AddTcpActiveConnection()
		go handleClientConnection(localConn, httpClient, cfg, key)
	}
}

func handleClientConnection(localConn net.Conn, httpClient *http.Client, cfg *config.Config, key []byte) {
	defer localConn.Close()
	defer stats.RemoveTcpActiveConnection()

	// SOCKS5 handshake
	if err := socks5Handshake(localConn); err != nil {
		return
	}

	// Read destination address
	destination, err := getSocks5Destination(localConn)
	if err != nil {
		return
	}

	payload := []byte(destination + "\n")
	encrypted, _ := crypto.Encrypt(payload, key)
	req, _ := masquerade.WrapInHttpRequest(encrypted, cfg.RemoteHost)

	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		written, _ := io.Copy(localConn, resp.Body)
		stats.AddTcpBytesOut(uint64(written))
	}()

	go func() {
		defer wg.Done()
		io.Copy(io.Discard, localConn)
	}()

	wg.Wait()
}

func manageConnection(httpClient *http.Client, cfg *config.Config, key []byte) {
	for {
		ping(httpClient, cfg, key)
		time.Sleep(30 * time.Second) // Health check interval
	}
}

func ping(httpClient *http.Client, cfg *config.Config, key []byte) {
	encrypted, _ := crypto.Encrypt([]byte("ping"), key)
	req, _ := masquerade.WrapInHttpRequest(encrypted, cfg.RemoteHost)

	resp, err := httpClient.Do(req)
	if err != nil {
		stats.SetLastSuccessfulPing(0)
		return
	}
	defer resp.Body.Close()

	encryptedResp, _ := masquerade.UnwrapFromHttpResponse(resp)
	decrypted, err := crypto.Decrypt(encryptedResp, key)

	if err == nil && string(decrypted) == "pong" {
		stats.SetLastSuccessfulPing(time.Now().Unix())
	}
}

// --- SOCKS5 Helper Functions ---
func socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 257)
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}
	// Respond that no authentication is required
	conn.Write([]byte{0x05, 0x00})
	return nil
}

func getSocks5Destination(conn net.Conn) (string, error) {
	buf := make([]byte, 257)
	_, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	// CMD (1 byte), RSV (1 byte), ATYP (1 byte)
	// We only support domain name for now
	if buf[3] != 0x03 {
		return "", fmt.Errorf("unsupported address type")
	}
	domainLen := int(buf[4])
	domain := string(buf[5 : 5+domainLen])
	port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
	return fmt.Sprintf("%s:%d", domain, port), nil
}
EOF

cat <<'EOF' > internal/tunnel/server.go
package tunnel

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/crypto"
	"github.com/ehsanking/elahe-tunnel/internal/logger"
	"github.com/ehsanking/elahe-tunnel/internal/masquerade"
	"github.com/ehsanking/elahe-tunnel/internal/stats"
	"github.com/pion/dtls/v2"
	"golang.org/x/time/rate"
)

func rateLimit(next http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(10), 50)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RunServer(key []byte) error {
	pingHandler := http.HandlerFunc(handlePingRequest(key))
	http.Handle("/favicon.ico", rateLimit(pingHandler))

	tunnelHandler := http.HandlerFunc(handleTunnelRequest(key))
	http.Handle("/", rateLimit(tunnelHandler))

	go runDtlsServer(key)

	logger.Info.Println("External server listening on :443")
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}

func runDtlsServer(key []byte) {
	udpAddr, _ := net.ResolveUDPAddr("udp", ":443")
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	dtlsListener, _ := dtls.Listen("udp", udpAddr, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})

	for {
		conn, _ := dtlsListener.Accept()
		go handleDtlsConnection(conn, key)
	}
}

func handleDtlsConnection(conn net.Conn, key []byte) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	parts := bytes.SplitN(buf[:n], []byte("\n"), 2)
	destination := string(parts[0])
	payload := parts[1]
	stats.AddUdpBytesIn(uint64(len(payload)))

	targetConn, _ := net.DialTimeout("udp", destination, 5*time.Second)
	defer targetConn.Close()
	targetConn.Write(payload)

	respBuf := make([]byte, 4096)
	n, _ = targetConn.Read(respBuf)
	response := append([]byte(destination+"\n"), respBuf[:n]...)
	bytesWritten, _ := conn.Write(response)
	stats.AddUdpBytesOut(uint64(bytesWritten))
}

func handleTunnelRequest(key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encrypted, _ := masquerade.UnwrapFromHttpRequest(r)
		decrypted, _ := crypto.Decrypt(encrypted, key)
		stats.AddTcpBytesIn(uint64(len(decrypted)))

		parts := bytes.SplitN(decrypted, []byte("\n"), 2)
		destination := string(parts[0])
		payload := parts[1]

		targetConn, _ := net.DialTimeout("tcp", destination, 5*time.Second)
		defer targetConn.Close()
		targetConn.Write(payload)

		respData, _ := io.ReadAll(targetConn)
		encryptedResp, _ := crypto.Encrypt(respData, key)
		stats.AddTcpBytesOut(uint64(len(encryptedResp)))

		masquerade.WrapInRandomHttpResponse(encryptedResp).Write(w)
	}
}
EOF

( 
    export GOPROXY=https://goproxy.io,direct
    export GOTOOLCHAIN=local
    go mod tidy
    go build -o elahe-tunnel -ldflags "-s -w" .
) &
spinner $!
wait $!

if [ ! -f "elahe-tunnel" ]; then
    echo -e "\n${RED}Compilation failed.${NC}"
    exit 1
fi
echo -e " ${GREEN}OK${NC}"

# 5. Install Binary and Cleanup
echo -n "Installing binary..."
mv elahe-tunnel /usr/local/bin/
chmod +x /usr/local/bin/elahe-tunnel
cd ..
rm -rf "$SOURCE_DIR" main.zip
echo -e " ${GREEN}OK${NC}"

# 6. Run Setup
echo -e "\n${GREEN}✅ Installation Complete!${NC}"
echo -e "Starting setup wizard...\n"
sleep 1
elahe-tunnel setup
